from time import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import SESSION_COOKIE, get_current_user
from app.core.config import get_settings
from app.core.email import send_account_email, smtp_is_configured
from app.core.rate_limit import RateLimiter, rate_limit_key
from app.core.security import (
    create_session_token,
    hash_password,
    hash_session_token,
    password_hash,
    verify_password,
)
from app.db.session import get_db
from app.models import AccountToken, AuthSession, User, UserPreference
from app.models.account_tokens import (
    account_token_expiry,
    create_account_token,
    hash_account_token,
)
from app.schemas.auth import (
    EmailVerificationConfirm,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    ProfileUpdate,
    RegisterRequest,
    UserRead,
)
from app.schemas.workflow import UserPreferencesRead, UserPreferencesUpdate

router = APIRouter(prefix="/api/auth")
login_limiter = RateLimiter(max_requests=10)
register_limiter = RateLimiter(max_requests=10)
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
DUMMY_PASSWORD_HASH = password_hash.hash("phishguard-invalid-account-password")


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=get_settings().environment == "production",
        samesite="lax",
        path="/",
    )


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    register_limiter.check(rate_limit_key(request, "register"))
    user = User(
        email=str(payload.email).strip().lower(),
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists.",
        ) from error
    db.refresh(user)
    return user


@router.post("/login", response_model=UserRead)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    login_limiter.check(rate_limit_key(request, "login"))
    email = str(payload.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
    if user is None or not user.is_active or not verify_password(
        payload.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_session_token()
    db.add(
        AuthSession(
            token_hash=hash_session_token(token),
            user_id=user.id,
            expires_at=int(time()) + SESSION_TTL_SECONDS,
        )
    )
    db.commit()
    _set_session_cookie(response, token)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        session = db.get(AuthSession, hash_session_token(token))
        if session is not None:
            db.delete(session)
            db.commit()
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=get_settings().environment == "production",
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserRead)
def current_user(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    return user


@router.put("/me", response_model=UserRead)
def update_profile(
    payload: ProfileUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user.email = str(payload.email).strip().lower()
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists.",
        ) from error
    db.refresh(user)
    return user


@router.get("/preferences", response_model=UserPreferencesRead)
def get_preferences(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> UserPreferencesRead:
    preferences = db.get(UserPreference, user.id)
    if preferences is None:
        return UserPreferencesRead(theme="system", compact_mode=False)
    return UserPreferencesRead(
        theme=preferences.theme,
        compact_mode=preferences.compact_mode,
        updated_at=preferences.updated_at,
    )


@router.put("/preferences", response_model=UserPreferencesRead)
def update_preferences(
    payload: UserPreferencesUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> UserPreferencesRead:
    preferences = db.get(UserPreference, user.id)
    if preferences is None:
        preferences = UserPreference(user_id=user.id)
        db.add(preferences)
    preferences.theme = payload.theme
    preferences.compact_mode = payload.compact_mode
    db.commit()
    db.refresh(preferences)
    return UserPreferencesRead(
        theme=preferences.theme,
        compact_mode=preferences.compact_mode,
        updated_at=preferences.updated_at,
    )


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    login_limiter.check(rate_limit_key(request, "password-reset"))
    if not smtp_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset email delivery is not configured.",
        )

    email = str(payload.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is not None and user.is_active:
        token = create_account_token()
        for old_token in db.scalars(
            select(AccountToken).where(
                AccountToken.user_id == user.id,
                AccountToken.kind == "password_reset",
            )
        ):
            db.delete(old_token)
        db.add(
            AccountToken(
                token_hash=hash_account_token(token),
                user_id=user.id,
                kind="password_reset",
                expires_at=account_token_expiry(),
            )
        )
        db.commit()
        try:
            send_account_email(
                user.email,
                "Reset your PhishGuard password",
                (
                    "A password reset was requested for your PhishGuard account.\n\n"
                    f"Reset token: {token}\n\n"
                    "This token expires after one hour. "
                    "If you did not request it, ignore this message."
                ),
            )
        except (OSError, RuntimeError) as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Password reset email could not be delivered.",
            ) from error

    return {"detail": "If the account exists, reset instructions have been sent."}


@router.post("/password-reset/confirm")
def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    token_hash = hash_account_token(payload.token)
    token = db.get(AccountToken, token_hash)
    now = int(time())
    if (
        token is None
        or token.kind != "password_reset"
        or token.used_at is not None
        or token.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or expired.",
        )

    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or expired.",
        )

    user.password_hash = hash_password(payload.password)
    token.used_at = now
    for session in db.scalars(
        select(AuthSession).where(AuthSession.user_id == user.id)
    ):
        db.delete(session)
    db.commit()
    return {"detail": "Password updated. Sign in again with the new password."}


@router.post("/email-verification/request", status_code=status.HTTP_202_ACCEPTED)
def request_email_verification(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    login_limiter.check(rate_limit_key(request, "email-verification"))
    if user.email_verified:
        return {"detail": "Email address is already verified."}
    if not smtp_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification email delivery is not configured.",
        )

    token = create_account_token()
    for old_token in db.scalars(
        select(AccountToken).where(
            AccountToken.user_id == user.id,
            AccountToken.kind == "email_verification",
        )
    ):
        db.delete(old_token)
    db.add(
        AccountToken(
            token_hash=hash_account_token(token),
            user_id=user.id,
            kind="email_verification",
            expires_at=account_token_expiry(),
        )
    )
    db.commit()
    try:
        send_account_email(
            user.email,
            "Verify your PhishGuard email",
            (
                "Verify your PhishGuard email address.\n\n"
                f"Verification token: {token}\n\n"
                "This token expires after one hour."
            ),
        )
    except (OSError, RuntimeError) as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Verification email could not be delivered.",
        ) from error
    return {"detail": "Verification instructions have been sent."}


@router.post("/email-verification/confirm")
def confirm_email_verification(
    payload: EmailVerificationConfirm,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    token_hash = hash_account_token(payload.token)
    token = db.get(AccountToken, token_hash)
    now = int(time())
    if (
        token is None
        or token.kind != "email_verification"
        or token.used_at is not None
        or token.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token is invalid or expired.",
        )

    user = db.get(User, token.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token is invalid or expired.",
        )
    user.email_verified = True
    token.used_at = now
    db.commit()
    return {"detail": "Email address verified."}

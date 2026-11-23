from hashlib import sha256
from secrets import token_urlsafe
from time import time


def create_account_token() -> str:
    return token_urlsafe(32)


def hash_account_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def account_token_expiry(seconds: int = 3600) -> int:
    return int(time()) + seconds

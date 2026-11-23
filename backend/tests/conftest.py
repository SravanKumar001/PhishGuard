import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth_routes import login_limiter, register_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture
def client():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event.listen(
        test_engine,
        "connect",
        lambda connection, record: connection.execute("PRAGMA foreign_keys=ON"),
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        with TestingSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


@pytest.fixture(autouse=True)
def clear_auth_rate_limits():
    login_limiter.reset()
    register_limiter.reset()


@pytest.fixture
def authenticated_client(client: TestClient) -> TestClient:
    credentials = {
        "email": "analyst@example.com",
        "password": "phishguard-test-password",
    }
    registered = client.post("/api/auth/register", json=credentials)
    assert registered.status_code == 201
    logged_in = client.post("/api/auth/login", json=credentials)
    assert logged_in.status_code == 200
    return client



import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.db.base import Base
from app.db.models.rbac import User, Role, Permission
from app.services.user_service import UserService
from app.db.base import get_db

# Set up an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the database dependency in the app
def override_get_db():
    print("Using in-memory SQLite database for testing")
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

# Create a test client
client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Set up the database before each test."""
    print("Setting up the in-memory SQLite database for testing")
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Create test data
    user = User(username="testuser", hashed_password="hashedpassword123", enabled=True)
    UserService.set_password(user, "securepassword")
    db.add(user)

    role = Role(name="admin", description="Administrator role")
    permission = Permission(name="read", description="Read permission")
    role.permissions.append(permission)
    user.roles.append(role)

    db.add(role)
    db.add(permission)
    db.commit()

    yield
    
    db.close()
    # Tear down the database after each test
    Base.metadata.drop_all(bind=engine)


def test_get_access_token_success():
    """Test the /auth/token endpoint with valid credentials."""
    response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "securepassword"},
    )
    assert response.status_code == 200
    response_data = response.json()
    assert "access_token" in response_data
    assert response_data["token_type"] == "bearer"
    assert response_data["username"] == "testuser"
    assert response_data["roles"] == ["admin"]
    assert response_data["permissions"] == ["read"]


def test_get_access_token_invalid_credentials():
    """Test the /auth/token endpoint with invalid credentials."""
    response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "wrongpassword"},
    )
    assert response.status_code == 500
    assert response.json()["detail"] == "An error occurred while authenticating the user with username testuser."


def test_update_password_success():
    """Test the /auth/update-password endpoint with valid data."""
    # First, get an access token
    token_response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "securepassword"},
    )
    access_token = token_response.json()["access_token"]

    # Update the password
    response = client.put(
        "/auth/update-password",
        json={
            "current_password": "securepassword",
            "new_password": "newsecurepassword",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json()["detail"] == "Password updated successfully."


def test_update_password_invalid_current_password():
    """Test the /auth/update-password endpoint with an invalid current password."""
    # First, get an access token
    token_response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "securepassword"},
    )
    access_token = token_response.json()["access_token"]

    # Attempt to update the password with an incorrect current password
    response = client.put(
        "/auth/update-password",
        json={
            "current_password": "wrongpassword",
            "new_password": "newsecurepassword",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Current password is incorrect."
import pytest
from sqlalchemy import StaticPool, create_engine
from sqlalchemy.orm import sessionmaker
# ⚠️ PATCH FIRST — before anything imports your routes or app
from unittest.mock import patch
# ⚠️ PATCH check_permissions to always return True
patch("app.core.security.check_permissions", lambda perms: lambda: True).start()
# ✅ THEN import FastAPI app — AFTER patch
from fastapi.testclient import TestClient
from app.main import app
from app.db.base import Base
from app.db.models.rbac import Role
from app.db.base import get_db

# Set up an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the database dependency in the app
def override_get_db():
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
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Add initial test data
    role = Role(name="admin", description="Administrator role")
    db.add(role)
    db.commit()

    yield

    # Tear down the database after each test
    Base.metadata.drop_all(bind=engine)


def test_create_user():
    """Test creating a new user."""
    response = client.post(
        "/users/",
        json={"username": "testuser", "password": "securepassword", "enabled": True},
    )
    assert response.status_code == 201
    response_data = response.json()
    assert response_data["username"] == "testuser"
    assert response_data["enabled"] is True


def test_read_all_users():
    """Test fetching all users."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    response = client.get("/users/")
    assert response.status_code == 200
    response_data = response.json()
    assert len(response_data) == 1
    assert response_data[0]["username"] == "testuser"
    assert response_data[0]["enabled"] is True


def test_read_user():
    """Test fetching a single user by ID."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    response = client.get("/users/1")
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["username"] == "testuser"
    assert response_data["enabled"] is True


def test_update_user():
    """Test updating an existing user."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    response = client.put(
        "/users/1",
        json={"username": "updateduser", "enabled": False},
    )
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["username"] == "updateduser"
    assert response_data["enabled"] is False


def test_delete_user():
    """Test deleting a user."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    response = client.delete("/users/1")
    assert response.status_code == 204

    # Verify the user is deleted
    response = client.get("/users/1")
    assert response.status_code == 404


def test_assign_roles_to_user():
    """Test assigning roles to a user."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    # Assign roles to the user
    response = client.post("/users/1/roles/", json=[1])
    assert response.status_code == 201
    response_data = response.json()
    assert len(response_data["roles"]) == 1
    assert response_data["roles"][0]["name"] == "admin"


def test_revoke_roles_from_user():
    """Test revoking roles from a user."""
    # Create a user first
    client.post("/users/", json={"username": "testuser", "password": "securepassword", "enabled": True})

    # Assign roles to the user
    client.post("/users/1/roles/", json=[1])

    # Revoke roles from the user
    response = client.request(
        "DELETE",
        "/users/1/roles/",
        json=[1],  # Send the payload as JSON
    )
    assert response.status_code == 200
    response_data = response.json()
    assert len(response_data["roles"]) == 0
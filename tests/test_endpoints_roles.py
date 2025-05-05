import json
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
from app.db.models.rbac import Permission
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
    permission = Permission(name="read", description="Read permission")
    db.add(permission)
    db.commit()

    yield

    # Tear down the database after each test
    Base.metadata.drop_all(bind=engine)


def test_create_role():
    """Test creating a new role."""
    response = client.post(
        "/roles/",
        json={"name": "admin", "description": "Administrator role"},
    )
    assert response.status_code == 201
    response_data = response.json()
    assert response_data["name"] == "admin"
    assert response_data["description"] == "Administrator role"


def test_read_all_roles():
    """Test fetching all roles."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    response = client.get("/roles/")
    assert response.status_code == 200
    response_data = response.json()
    assert len(response_data) == 1
    assert response_data[0]["name"] == "admin"
    assert response_data[0]["description"] == "Administrator role"


def test_read_role():
    """Test fetching a single role by ID."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    response = client.get("/roles/1")
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["name"] == "admin"
    assert response_data["description"] == "Administrator role"


def test_update_role():
    """Test updating an existing role."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    response = client.put(
        "/roles/1",
        json={"name": "superadmin", "description": "Updated administrator role"},
    )
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["name"] == "superadmin"
    assert response_data["description"] == "Updated administrator role"


def test_delete_role():
    """Test deleting a role."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    response = client.delete("/roles/1")
    assert response.status_code == 204

    # Verify the role is deleted
    response = client.get("/roles/1")
    assert response.status_code == 404


def test_assign_permissions_to_role():
    """Test assigning permissions to a role."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    # Assign permissions to the role
    response = client.post("/roles/1/permissions/", json=[1])
    assert response.status_code == 201
    response_data = response.json()
    assert len(response_data["permissions"]) == 1
    assert response_data["permissions"][0]["name"] == "read"


def test_revoke_permissions_from_role():
    """Test revoking permissions from a role."""
    # Create a role first
    client.post("/roles/", json={"name": "admin", "description": "Administrator role"})

    # Assign permissions to the role
    client.post("/roles/1/permissions/", json=[1])

    # Revoke permissions from the role
    response = client.request(
        "DELETE",
        "/roles/1/permissions/",
        json=[1],  # Send the payload as JSON
    )

    assert response.status_code == 200
    response_data = response.json()
    assert len(response_data["permissions"]) == 0
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


def test_create_permission():
    """Test creating a new permission."""
    response = client.post(
        "/permissions/",
        json={"name": "write", "description": "Write permission"},
    )
    assert response.status_code == 201
    response_data = response.json()
    assert response_data["name"] == "write"
    assert response_data["description"] == "Write permission"


def test_read_all_permissions():
    """Test fetching all permissions."""
    response = client.get("/permissions/")
    assert response.status_code == 200
    response_data = response.json()
    assert len(response_data) == 1
    assert response_data[0]["name"] == "read"
    assert response_data[0]["description"] == "Read permission"


def test_read_permission():
    """Test fetching a single permission by ID."""
    response = client.get("/permissions/1")
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["name"] == "read"
    assert response_data["description"] == "Read permission"


def test_update_permission():
    """Test updating an existing permission."""
    response = client.put(
        "/permissions/1",
        json={"name": "read_updated", "description": "Updated read permission"},
    )
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["name"] == "read_updated"
    assert response_data["description"] == "Updated read permission"


def test_delete_permission():
    """Test deleting a permission."""
    response = client.delete("/permissions/1")
    assert response.status_code == 204

    # Verify the permission is deleted
    response = client.get("/permissions/1")
    assert response.status_code == 404
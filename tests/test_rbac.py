import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.db.models.rbac import User, Role, Permission, UserRole, RolePermission

# Set up an in-memory SQLite database for testing
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Fixture to set up and tear down the database
@pytest.fixture(scope="function")
def db_session():
    print("Setting up the in-memory SQLite database for testing")
    # Create all tables
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    # Drop all tables
    Base.metadata.drop_all(bind=engine)


def test_create_user(db_session):
    """Test creating a User."""
    user = User(username="testuser", hashed_password="hashedpassword123")
    db_session.add(user)
    db_session.commit()

    # Verify the user was created
    created_user = db_session.query(User).filter_by(username="testuser").first()
    assert created_user is not None
    assert created_user.username == "testuser"
    assert created_user.hashed_password == "hashedpassword123"
    assert created_user.enabled is True


def test_create_role(db_session):
    """Test creating a Role."""
    role = Role(name="admin", description="Administrator role")
    db_session.add(role)
    db_session.commit()

    # Verify the role was created
    created_role = db_session.query(Role).filter_by(name="admin").first()
    assert created_role is not None
    assert created_role.name == "admin"
    assert created_role.description == "Administrator role"


def test_create_permission(db_session):
    """Test creating a Permission."""
    permission = Permission(name="read", description="Read permission")
    db_session.add(permission)
    db_session.commit()

    # Verify the permission was created
    created_permission = db_session.query(Permission).filter_by(name="read").first()
    assert created_permission is not None
    assert created_permission.name == "read"
    assert created_permission.description == "Read permission"


def test_user_role_relationship(db_session):
    """Test the many-to-many relationship between User and Role."""
    user = User(username="testuser", hashed_password="hashedpassword123")
    role = Role(name="admin", description="Administrator role")
    user.roles.append(role)

    db_session.add(user)
    db_session.commit()

    # Verify the relationship
    created_user = db_session.query(User).filter_by(username="testuser").first()
    assert created_user is not None
    assert len(created_user.roles) == 1
    assert created_user.roles[0].name == "admin"


def test_role_permission_relationship(db_session):
    """Test the many-to-many relationship between Role and Permission."""
    role = Role(name="admin", description="Administrator role")
    permission = Permission(name="read", description="Read permission")
    role.permissions.append(permission)

    db_session.add(role)
    db_session.commit()

    # Verify the relationship
    created_role = db_session.query(Role).filter_by(name="admin").first()
    assert created_role is not None
    assert len(created_role.permissions) == 1
    assert created_role.permissions[0].name == "read"
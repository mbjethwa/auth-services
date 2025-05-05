from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.db.models.rbac import User, Role, Permission
from app.core.config import settings

# Define your database URL
SQLALCHEMY_DATABASE_URL = str(settings.SQLALCHEMY_DATABASE_URL)

# Create the database engine
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)

# Initialize sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Initialize some initial data
initial_data = {
    "users": [
        {
            "username": "admin",
            "password": "admin@test@2025",
            "roles": [
                "admin_AUTH_SERVICE",
                "admin_INVENTORY_SERVICE",
                "admin_ORDER_SERVICE",
            ],
        }
    ],
    "roles": [
        {
            "name": "admin_AUTH_SERVICE",
            "description": "admin role for AUTH_SERVICE",
            "permissions": [
                "manage_users_AUTH_SERVICE",
                "view_users_AUTH_SERVICE",
                "manage_roles_AUTH_SERVICE",
                "view_roles_AUTH_SERVICE",
                "manage_permissions_AUTH_SERVICE",
                "view_permissions_AUTH_SERVICE",
            ],
        },
        {
            "name": "user_AUTH_SERVICE",
            "description": "user role for AUTH_SERVICE",
            "permissions": [
                "view_users_AUTH_SERVICE",
                "view_roles_AUTH_SERVICE",
                "view_permissions_AUTH_SERVICE",
            ],
        },
        {
            "name": "admin_INVENTORY_SERVICE",
            "description": "admin role for INVENTORY_SERVICE",
            "permissions": [
                "manage_items_INVENTORY_SERVICE",
                "view_items_INVENTORY_SERVICE",
            ],
        },
        {
            "name": "user_INVENTORY_SERVICE",
            "description": "user role for INVENTORY_SERVICE",
            "permissions": ["view_items_INVENTORY_SERVICE"],
        },
        {
            "name": "admin_ORDER_SERVICE",
            "description": "admin role for ORDER_SERVICE",
            "permissions": ["manage_orders_ORDER_SERVICE", "view_orders_ORDER_SERVICE"],
        },
        {
            "name": "user_ORDER_SERVICE",
            "description": "user role for ORDER_SERVICE",
            "permissions": ["view_orders_ORDER_SERVICE"],
        },
    ],
    "permissions": [
        {
            "name": "manage_users_AUTH_SERVICE",
            "description": "Permission for manage_users in AUTH_SERVICE",
        },
        {
            "name": "view_users_AUTH_SERVICE",
            "description": "Permission for view_users in AUTH_SERVICE",
        },
        {
            "name": "manage_roles_AUTH_SERVICE",
            "description": "Permission for manage_roles in AUTH_SERVICE",
        },
        {
            "name": "view_roles_AUTH_SERVICE",
            "description": "Permission for view_roles in AUTH_SERVICE",
        },
        {
            "name": "manage_permissions_AUTH_SERVICE",
            "description": "Permission for manage_permissions in AUTH_SERVICE",
        },
        {
            "name": "view_permissions_AUTH_SERVICE",
            "description": "Permission for view_permissions in AUTH_SERVICE",
        },
        {
            "name": "manage_items_INVENTORY_SERVICE",
            "description": "Permission for manage_items in INVENTORY_SERVICE",
        },
        {
            "name": "view_items_INVENTORY_SERVICE",
            "description": "Permission for view_items in INVENTORY_SERVICE",
        },
        {
            "name": "manage_orders_ORDER_SERVICE",
            "description": "Permission for manage_orders in ORDER_SERVICE",
        },
        {
            "name": "view_orders_ORDER_SERVICE",
            "description": "Permission for view_orders in ORDER_SERVICE",
        },
        {
            "name": "deduct_items_INVENTORY_SERVICE",
            "description": "Permission for deduct_items in INVENTORY_SERVICE",
        }
    ],
}


# Helper function to create roles and permissions
def create_roles_and_permissions(db_session):
    # Based on initial data object, create permissions in database
    for permission in initial_data["permissions"]:
        new_permission = Permission(
            name=permission["name"],
            description=permission["description"],
        )
        db_session.add(new_permission)
        db_session.commit()

    # Based on initial data object, create roles in database
    for role in initial_data["roles"]:
        new_role = Role(
            name=role["name"],
            description=role["description"],
        )
        db_session.add(new_role)
        db_session.commit()
        db_session.refresh(new_role)  # Refresh to get the new role ID

        # Create permissions for this role
        for perm in role["permissions"]:
            stmt = select(Permission).where(Permission.name == perm)
            permission_model = db_session.execute(stmt).scalars().first()
            stmt = select(Role).where(Role.role_id == new_role.role_id)
            role_model = db_session.execute(stmt).scalars().first()
            role_model.permissions.append(permission_model)
        db_session.commit()


# Function to create an admin user for each service
def create_admin_user(db_session):
    # Create admin user
    admin_user = User(
        username="admin", hashed_password="hashed_admin_password", enabled=True
    )
    admin_user = User(
        username=initial_data["users"][0]["username"],
        hashed_password=settings.bcrypt_context.hash(
            initial_data["users"][0]["password"]
        ),
    )
    db_session.add(admin_user)
    db_session.commit()
    db_session.refresh(admin_user)  # Refresh to get the new user ID

    # Assign roles to the admin user
    roles = (
        db_session.query(Role).filter(Role.name.like("admin_%")).all()
    )  # Fetch all admin roles
    for role in roles:
        admin_user.roles.append(role)

    db_session.commit()


# Main function to initialize DB and data
def initialize_db():
    # Create the database schema if it doesn't exist
    Base.metadata.create_all(bind=engine)

    # Open a session to interact with the database
    db_session = SessionLocal()
    try:
        # Check if the database is already initialized
        existing_user = db_session.query(User).first()
        if existing_user:
            print("Existing user found:", existing_user.username)
            return False  # Database is already initialized

        # Insert default users or data here
        print("Initializing database with default values...")

        # Create roles, permissions, and admin user
        create_roles_and_permissions(db_session)
        create_admin_user(db_session)

        return True  # Database initialized successfully
    except Exception as e:
        print(f"Error during database initialization: {e}")
        return False
    finally:
        db_session.close()


if __name__ == "__main__":
    if initialize_db():
        print("Database initialized and initial data seeded successfully.")
    else:
        print("Database already initialized. Skipping initDB.")

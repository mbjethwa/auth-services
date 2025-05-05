from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    func,
    ForeignKey,
    Table,
)
from sqlalchemy.orm import relationship
from app.db.base import Base


# All models relate to RBAC


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True)

    # Created at timestamp
    created_at = Column(DateTime, server_default=func.now())

    # Updated at timestamp
    updated_at = Column(DateTime, onupdate=func.now())

    # Define the many-to-many relationship between Role and Permission using back_populates
    roles = relationship("Role", secondary="users_roles", back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=False)

    # Created at timestamp
    created_at = Column(DateTime, server_default=func.now())

    # Updated at timestamp
    updated_at = Column(DateTime, onupdate=func.now())

    # Define the many-to-many relationship between Role and Permission with back_populates
    users = relationship("User", secondary="users_roles", back_populates="roles")
    permissions = relationship(
        "Permission", secondary="roles_permissions", back_populates="roles"
    )


class Permission(Base):
    __tablename__ = "permissions"

    permission_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=False)

    # Created at timestamp
    created_at = Column(DateTime, server_default=func.now())

    # Updated at timestamp
    updated_at = Column(DateTime, onupdate=func.now())

    # Define the relationship with back_populates
    roles = relationship(
        "Role", secondary="roles_permissions", back_populates="permissions"
    )


# Association table for the many-to-many relationship between User and Role
UserRole = Table(
    "users_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.user_id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.role_id"), primary_key=True),
)


# Association table for the many-to-many relationship between Role and Permission
RolePermission = Table(
    "roles_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.role_id"), primary_key=True),
    Column(
        "permission_id",
        Integer,
        ForeignKey("permissions.permission_id"),
        primary_key=True,
    ),
)

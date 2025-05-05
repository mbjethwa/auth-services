# Pydantic models for request/response validation, keep separate from database models

from pydantic import BaseModel, Field
from typing import Optional

from app.schemas.permission import PermissionReadRequest


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)  # Required field
    description: str = Field(..., min_length=1, max_length=255)  # Required field


class RoleReadRequest(BaseModel):
    role_id: int
    name: str
    description: str
    permissions: list[PermissionReadRequest] = (
        []
    )  # Nested PermissionReadRequest models to include all permissions under this role

    class Config:
        from_attributes = True  # Enables compatibility with SQLAlchemy models


class RoleUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=50)  # Optional field
    description: Optional[str] = Field(
        None, min_length=1, max_length=255
    )  # Optional field

# Pydantic models for request/response validation, keep separate from database models

from pydantic import BaseModel, Field
from typing import Optional

# from .role import RoleReadRequest


class PermissionCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)  # Required field
    description: str = Field(..., min_length=1, max_length=255)  # Required field


class PermissionReadRequest(BaseModel):
    permission_id: int
    name: str
    description: str

    class Config:
        from_attributes = True  # Enables compatibility with SQLAlchemy models


class PermissionUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=50)  # Optional field
    description: Optional[str] = Field(
        None, min_length=1, max_length=255
    )  # Optional field

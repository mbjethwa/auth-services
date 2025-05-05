# Pydantic models for request/response validation, keep separate from database models

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

from .role import RoleReadRequest


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)  # Required field
    password: str = Field(..., min_length=8)  # Required field
    enabled: bool = Field(default=True)  # Optional field with default value


class UserReadRequest(BaseModel):
    user_id: int
    username: str
    enabled: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    roles: list[RoleReadRequest] = (
        []
    )  # Nested RoleReadRequest models to include roles assigned to this user, roles key must match the relationship key in the User model

    class Config:
        from_attributes = True  # Enables compatibility with SQLAlchemy models


class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=1, max_length=50)  # Optional field
    enabled: Optional[bool] = Field(None)  # Optional field


class UpdateUserPasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)

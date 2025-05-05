import pytest
from datetime import timedelta, datetime, timezone
from jose import jwt
from app.core.security import create_access_token
from app.core.config import settings


def test_create_access_token_valid():
    # Arrange
    username = "testuser"
    user_id = 1
    roles = ["admin"]
    permissions = ["read", "write"]
    expires_delta = timedelta(minutes=15)

    # Act
    token = create_access_token(
        username=username,
        user_id=user_id,
        roles=roles,
        permissions=permissions,
        expires_delta=expires_delta,
    )
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    # Assert
    assert payload["username"] == username
    assert payload["user_id"] == user_id
    assert payload["roles"] == roles
    assert payload["permissions"] == permissions
    assert "exp" in payload


def test_create_access_token_expiration():
    # Arrange
    username = "testuser"
    user_id = 1
    roles = ["admin"]
    permissions = ["read", "write"]
    expires_delta = timedelta(seconds=10)

    # Act
    token = create_access_token(
        username=username,
        user_id=user_id,
        roles=roles,
        permissions=permissions,
        expires_delta=expires_delta,
    )
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    # Assert
    expected_exp = datetime.now(timezone.utc) + expires_delta
    assert abs(payload["exp"] - expected_exp.timestamp()) < 2  # Allow small time drift


def test_create_access_token_remember_me():
    # Arrange
    username = "testuser"
    user_id = 1
    roles = ["admin"]
    permissions = ["read", "write"]
    remember_me = True

    # Act
    token = create_access_token(
        username=username,
        user_id=user_id,
        roles=roles,
        permissions=permissions,
        remember_me=remember_me,
    )
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    # Assert
    expected_exp = datetime.now(timezone.utc) + timedelta(
        days=settings.ACCESS_TOKEN_EXPIRE_DAYS_WITH_REMEMBER_ME
    )
    assert abs(payload["exp"] - expected_exp.timestamp()) < 2  # Allow small time drift
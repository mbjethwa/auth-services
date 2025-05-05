from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette import status
from app.core.config import settings
from app.db.models.rbac import User
from app.db.base import get_db
from app.services.user_service import UserService


db_dependency = Annotated[Session, Depends(get_db)]


def authenticate_user(username: str, password: str, db: db_dependency):
    # Fetch the user from DB
    stmt = select(User).where(User.username == username)
    user_model = db.execute(stmt).scalars().first()
    # Check if user exists and is enabled
    if user_model is None:
        return False
    if not user_model.enabled:
        return False

    # Verify credentials against DB
    # if not settings.bcrypt_context.verify(password, user_model.hashed_password):  # type: ignore
    if not UserService.check_password(user_model, password):
        return False

    return user_model


def create_access_token(
    username: str,
    user_id: int,
    roles: list[str],
    permissions: list[str],
    expires_delta: Optional[timedelta] = None,
    remember_me: bool = False,
):
    encode = {
        "username": username,
        "user_id": user_id,
        "roles": roles,
        "permissions": permissions,
    }

    # Add the expiration time to the payload
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    elif remember_me:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.ACCESS_TOKEN_EXPIRE_DAYS_WITH_REMEMBER_ME
        )
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    encode.update({"exp": expire})

    return jwt.encode(encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)


# Dependency that extracts the token from the cookies
def get_token_from_cookies(request: Request):
    token = request.cookies.get(
        "access_token"
    )  # access_token is the name of your cookie
    if not token:
        return None
    # print("get_token_from_cookies", token)
    return token


# Combined dependency to check both cookies and Authorization header
def validate_token(
    authorization_token: Optional[str] = Depends(settings.oauth2_bearer),
):

    if not authorization_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        # Decode the JWT token
        payload = jwt.decode(
            authorization_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        # Validate the token payload
        username: str = payload.get("username")  # type: ignore
        user_id: int = payload.get("user_id")  # type: ignore

        # Check expiration
        exp_timestamp = payload.get("exp")
        if exp_timestamp is None or datetime.fromtimestamp(exp_timestamp, timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
            )

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload is invalid.",
            )

        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired.",
        ) from e


# Old Reference Note: if passing token in header:
# token: Annotated[str, Depends(settings.oauth2_bearer)] to access Authorization header
def get_current_user(
    token_payload: Annotated[dict, Depends(validate_token)], db: db_dependency
):
    try:
        # Verify user against DB
        stmt = select(User).where(User.username == token_payload["username"])
        user_model = db.execute(stmt).scalars().first()

        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate user.",
            )

        return user_model

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user."
        )


def check_permissions(required_permissions: list[str]):
    """
    Check if the current user has the required permission.

    Args:
        required_permission (list[str]): The list of possible permissions to perform an action.

    Returns:
        function: A permission checker function that raises an HTTPException if the user lacks the required permission.
    """

    def permission_checker(payload: dict = Depends(validate_token)):
        user_permissions = payload.get("permissions", [])

        # Check if user has one of the required permissions
        if not any(
            permission in user_permissions for permission in required_permissions
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted because of insufficient permissions",
            )

    return permission_checker


def check_roles(required_roles: list[str]):
    """
    Check if the current user has the required role.

    Args:
        required_roles (list[str]): The roles required to perform an action.

    Returns:
        function: A role checker function that raises an HTTPException if the user lacks the required role.
    """

    def role_checker(payload: dict = Depends(validate_token)):
        user_roles = payload.get("roles", [])
        # Check if the user has the required role, match the role name, only one role is required
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted because of insufficient roles",
            )

    return role_checker

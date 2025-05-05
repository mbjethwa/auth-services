import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm
from app.db.base import get_db
from app.core.config import settings
from app.core.security import authenticate_user, create_access_token, get_current_user
from app.schemas.user import UpdateUserPasswordRequest
from app.db.models.rbac import User
from app.services.user_service import UserService


router = APIRouter(prefix="/auth", tags=["Authentication"])

db_dependency = Annotated[Session, Depends(get_db)]


@router.post(
    "/token"
)  # full route will be /auth/token matching the tokenUrl of OAuth2PasswordBearer
def get_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
    remember_me: bool = Form(False),  # Add remember_me field with default value False
):
    """
    Handles the process of obtaining an access token for a user.

    Args:

        - form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
        - db (Session): The database session dependency.
        - remember_me (Bool): The form data containing the remember_me field to return a token with longer validity. Default is False.

    Returns:

        - dict: A dictionary containing the access token and token type. Example:
        {
            "access_token": "eyJhbGckpXVCJ9.eyJzdWIiOiJ1c2VyM",
            "token_type": "bearer",
            "user_id": 2,
            "username": Manager,
            "roles": ["Manager"],
            "permissions": ["read", "write"],
        }

    Raises:

        - HTTPException: If the user cannot be authenticated, or if any database or unexpected errors occur.
    """
    try:
        # print(form_data.username, form_data.password)
        # print(remember_me)
        user = authenticate_user(form_data.username, form_data.password, db)
        # get a list of all roles names for the user
        user_roles = [role.name for role in user.roles]
        # get a list of all permissions names for the user
        user_permissions = [
            permission.name for role in user.roles for permission in role.permissions
        ]
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate the user with username {form_data.username}.",
            )
        token = create_access_token(user.username, user.user_id, user_roles, user_permissions, remember_me=remember_me)  # type: ignore

        # Convert roles to a list of role names
        roles = [role.name for role in user.roles]
        # Convert permissions to a list of permission names
        permissions = [
            permission.name for role in user.roles for permission in role.permissions
        ]
        response_data = {
            "access_token": token,
            "token_type": settings.ACCESS_TOKEN_TYPE,
            "user_id": user.user_id,
            "username": user.username,
            "roles": roles,
            "permissions": permissions,
        }
        # print(response_data)
        response = JSONResponse(content=response_data)
        return response

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while authenticating the user with username {form_data.username}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while authenticating the user with username {form_data.username}.",
        )


@router.put(
    "/update-password",
    response_model=dict,
    status_code=status.HTTP_200_OK,
    response_description="Password updated successfully.",
)
def update_password(
    update_password_request: UpdateUserPasswordRequest,
    db: db_dependency,
    current_user: User = Depends(get_current_user),
):
    # print("Current User: ", current_user.username)
    try:
        # Verify the current password
        if not UserService.check_password(
            current_user, update_password_request.current_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect.",
            )

        # Set the new password
        UserService.set_password(current_user, update_password_request.new_password)

        # Update the user's password in the database
        db.add(current_user)
        db.commit()

        return {"detail": "Password updated successfully."}

    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise e
    except Exception as e:
        logging.error(f"An error occurred while updating the password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the password.",
        )

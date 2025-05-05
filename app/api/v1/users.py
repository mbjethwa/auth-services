import logging
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import asc, delete, desc, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette import status
from app.core.config import settings
from app.core.security import check_permissions
from app.db.models.rbac import Role, User
from app.db.base import get_db
from app.schemas.user import UserCreateRequest, UserReadRequest, UserUpdateRequest


db_dependency = Annotated[Session, Depends(get_db)]

router = APIRouter(prefix="/users", tags=["Users"])


@router.post(
    "/",
    response_model=UserReadRequest,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_permissions(["manage_users_AUTH_SERVICE"]))],
)
def create_user(db: db_dependency, user_request: UserCreateRequest):
    """
    Create a new user in the database.

    Args:

        User_request (UserCreateRequest): The request object containing user details.
        - username (str): The username of the user.
        - password (str): The password of the user.
        - enabled (bool): The status of the user. Default is True.
    Returns:

        User: The newly created user model instance (status code 201).
    Raises:

        ValidationError: If the request body is invalid (status code 422).
        HTTPException: If the user with the given ID is not found, or if there is an integrity error or other database error.
    """

    try:
        # with db.begin():  # Automatically commits or rolls back on exit
        user_model = User(
            username=user_request.username,
            hashed_password=settings.bcrypt_context.hash(user_request.password),
        )

        db.add(
            user_model
        )  # create a new instance of a model that is not yet added to the session
        db.commit()
        # Must be outside "with" block to ensure to commit the transaction first
        db.refresh(user_model)  # Refresh the new instance

        return user_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the new user.",
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the new user.",
        )


@router.get(
    "/",
    response_model=list[UserReadRequest],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            check_permissions(["manage_users_AUTH_SERVICE", "view_users_AUTH_SERVICE"])
        )
    ],
)
def read_all_users(
    db: db_dependency,
    limit: Optional[int] = Query(None, description="Number of records to return"),
    order_by: Optional[str] = Query(None, description="Order by column"),
    ascending: Optional[bool] = Query(True, description="Sort in ascending order"),
):
    """
    Fetches all users from the database along with their associated roles.
    Args:

        limit (int, optional): The number of records to return. Defaults to None.
        order_by (str, optional): The column to order the results by. Defaults to user_id.
        ascending (bool, optional): Sort in ascending order. Defaults to True.
        Note: the allowed columns are "user_id", "username".
    Returns:

        list[User]: A list of User objects with their roles loaded.
    Raises:

        HTTPException: If an integrity error or any other database error occurs or if an unexpected error occurs.
    """

    try:
        allowed_columns = [
            "user_id",
            "username",
        ]  # Add valid column names here

        # Start building the query
        stmt = select(User)

        # Apply ordering
        # Validate and set the order_by column or a default value
        if order_by is None:
            order_by = "user_id"
        order_by = (
            order_by.lower() if order_by.lower() in allowed_columns else "user_id"
        )
        order_column = getattr(User, order_by)
        if order_column:
            if ascending:
                stmt = stmt.order_by(asc(order_column))
            else:
                stmt = stmt.order_by(desc(order_column))

        # Apply limit
        if limit is not None:
            stmt = stmt.limit(limit)

        # Execute the query
        return db.execute(stmt).scalars().all()

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching all users.",
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching all users.",
        )


@router.get(
    "/{user_id}",
    response_model=UserReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            check_permissions(["manage_users_AUTH_SERVICE", "view_users_AUTH_SERVICE"])
        )
    ],
)
def read_user(db: db_dependency, user_id: int = Path(gt=0)):
    """
    Fetch a user by user_id from the database.
    Args:

        user_id (int): The ID of the user to fetch. Must be greater than 0.
    Returns:

        User: The user model if found.
    Raises:

        HTTPException: If the user with the given ID is not found, or if there is an integrity error or other database error.
    """

    try:
        stmt = select(User).where(User.user_id == user_id)
        user_model = db.execute(stmt).scalars().first()

        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id {user_id} not found.",
            )

        return user_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while fetching the user with id {user_id}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while fetching the user with id {user_id}.",
        )


@router.put(
    "/{user_id}",
    response_model=UserReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(check_permissions(["manage_users_AUTH_SERVICE"]))],
)
def update_user(
    db: db_dependency,
    user_request: UserUpdateRequest,
    user_id: int = Path(gt=0),
):
    """
    Update an existing user in the database.
    Args:

        user_request (UserUpdateRequest): The request object containing the fields to update.
        - username (str): The username of the user.
        - password (str): The password of the user.
        - enabled (bool): The status of the user.
        user_id (int): The ID of the user to update. Must be greater than 0.
    Returns:

        user_model: The updated user model.
    Raises:

        HTTPException: If the user with the given ID is not found, or if there is an integrity error or other database error.
    """

    try:
        stmt = select(User).where(User.user_id == user_id)
        user_model = db.execute(stmt).scalars().first()

        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id {user_id} not found.",
            )

        # Loop through provided fields and update the corresponding fields in user_model
        update_data = user_request.model_dump(
            exclude_unset=True
        )  # Only get the provided fields

        for key, value in update_data.items():
            setattr(user_model, key, value)  # Dynamically update the fields

        db.commit()
        db.refresh(user_model)  # Refresh the updated instance
        return user_model  # Return the updated user model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the user with id {user_id}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the user with id {user_id}.",
        )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(check_permissions(["manage_users_AUTH_SERVICE"]))],
)
def delete_user(db: db_dependency, user_id: int = Path(gt=0)):
    """
    Delete a user from the database by their user ID.
    Args:

        user_id (int): The ID of the user to delete. Must be greater than 0.
    Raises:

        HTTPException: If the user with the given ID is not found, or if there is an integrity error or other database error.
    Returns:
        None
    """

    try:
        stmt = select(User).where(User.user_id == user_id)
        user_model = db.execute(stmt).scalars().first()
        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id {user_id} not found.",
            )

        stmt = delete(User).where(User.user_id == user_id)
        db.execute(stmt)
        db.commit()

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the user with id {user_id}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the user with id {user_id}.",
        )


# Create a new APIRouter instance for User-Role Router: Manages the relationships between users and roles, enabling you to assign or remove roles from users.
user_role = APIRouter(
    prefix="/users/{user_id}/roles",
    tags=["Users"],
)


@user_role.post(
    "/",
    response_model=UserReadRequest,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_permissions(["manage_users_AUTH_SERVICE"]))],
)
def assign_roles(
    roles_request: list[
        int
    ],  # Expect to receive a list of role ids not yet assigned to this role
    db: db_dependency,
    user_id: int = Path(gt=0),
):
    """
    Assigns roles to a user based on the provided list of role IDs.
    Args:

        user_id (int): The ID of the user to whom the roles will be assigned. Must be greater than 0.
        roles_request (list[int]): A list of role IDs to be assigned to the user.
    Returns:

        User: The user model with the newly assigned roles.
    Raises:

        HTTPException: If the user is not found, if one or more roles are not found,
                       if there is an integrity error, or if any other database error occurs.
    """

    try:
        stmt = select(User).where(User.user_id == user_id)
        user_model = db.execute(stmt).scalars().first()

        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"user with id {user_id} not found.",
            )

        # Verify if any role to be added is not existing in the Role table
        stmt = select(Role).where(Role.role_id.in_(roles_request))
        existing_roles = db.execute(stmt).scalars().all()
        if len(existing_roles) != len(roles_request):
            # Initialize a new list of type integer to store non-matching role IDs
            not_existing_role_ids: list[int] = []

            # Loop through each role ID in roles_request
            for role_id in roles_request:
                # Check if the role ID is not in the list of existing role IDs
                if not any(role_id == role.role_id for role in existing_roles):
                    # Add to the new list if it doesn't exist in existing_roles
                    not_existing_role_ids.append(role_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"One or more roles not found: {not_existing_role_ids}",
            )

        # Assign the role to the role
        for role in existing_roles:
            if role not in user_model.roles:
                # this auto maps the models then add records to UserRole table
                user_model.roles.append(role)

        db.commit()
        db.refresh(user_model)  # Refresh the new instance
        return user_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while assigning roles to the user with id {user_id}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while assigning roles to the user with id {user_id}.",
        )


@user_role.delete(
    "/",
    response_model=UserReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(check_permissions(["manage_users_AUTH_SERVICE"]))],
)
def revoke_roles(
    roles_request: list[
        int
    ],  # Expect to receive a list of role ids not yet assigned to this role
    db: db_dependency,
    user_id: int = Path(gt=0),
):
    """
    Revoke specified roles from a user.
    This function removes roles from a user based on the provided list of role IDs.
    It checks if the roles exist and if they are assigned to the user before revoking them.
    Args:

        roles_request (list[int]): A list of role IDs to be revoked from the user.
        user_id (int): The ID of the user to whom the roles will be assigned. Must be greater than 0.
    Returns:

        The updated user model with the roles revoked.
    Raises:

        HTTPException: If the user is not found, if one or more roles are not found, or if any database error occurs.
    """

    try:
        stmt = select(User).where(User.user_id == user_id)
        user_model = db.execute(stmt).scalars().first()

        if user_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"user with id {user_id} not found.",
            )

        # Verify if any role to be removed is not existing in the Permission table
        stmt = select(Role).where(Role.role_id.in_(roles_request))
        existing_roles = db.execute(stmt).scalars().all()
        if len(existing_roles) != len(roles_request):
            # Initialize a new list of type integer to store non-matching role IDs
            not_existing_role_ids: list[int] = []

            # Loop through each role ID in roles_request
            for role_id in roles_request:
                # Check if the role ID is not in the list of existing role IDs
                if not any(role_id == role.role_id for role in existing_roles):
                    # Add to the new list if it doesn't exist in existing_roles
                    not_existing_role_ids.append(role_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"One or more roles not found: {not_existing_role_ids}",
            )

        # Revoke the role to the role
        for role in existing_roles:
            if role in user_model.roles:
                # this auto maps the models then add records to RolePermission table
                user_model.roles.remove(role)

        db.commit()
        db.refresh(user_model)  # Refresh the new instance
        return user_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while revoking roles from the user with id {user_id}.",
        )
    except HTTPException as e:
        logging.error(f"HTTPException: {str(e)}")
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while revoking roles from the user with id {user_id}.",
        )

import logging
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import asc, delete, desc, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette import status
from app.core.security import check_permissions
from app.db.models.rbac import Permission, Role
from app.db.base import get_db
from app.schemas.role import RoleCreateRequest, RoleReadRequest, RoleUpdateRequest


db_dependency = Annotated[Session, Depends(get_db)]

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.post(
    "/",
    response_model=RoleReadRequest,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_permissions(["manage_roles_AUTH_SERVICE"]))],
)
def create_role(db: db_dependency, role_request: RoleCreateRequest):
    """
    Create a new role in the database.
    Args:

        role_request (RoleCreateRequest): The request object containing the details of the role to create.
        - name (str): The name of the role.
        - description (str): The description of the role.
    Returns:

        Role: The newly created role model instance.
    Raises:

        HTTPException: If an integrity error or any other database error occurs, or if an unexpected error occurs.
    """

    try:
        role_model = Role(
            name=role_request.name,
            description=role_request.description,
        )

        db.add(
            role_model
        )  # create a new instance of a model that is not yet added to the session

        db.commit()
        db.refresh(role_model)  # Refresh the new instance

        return role_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the new role.",
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the new role.",
        )


@router.get(
    "/",
    dependencies=[
        Depends(
            check_permissions(["manage_roles_AUTH_SERVICE", "view_roles_AUTH_SERVICE"])
        )
    ],
    response_model=list[RoleReadRequest],
    status_code=status.HTTP_200_OK,
)
def read_all_roles(
    db: db_dependency,
    limit: Optional[int] = Query(None, description="Number of records to return"),
    order_by: Optional[str] = Query(None, description="Order by column"),
    ascending: Optional[bool] = Query(True, description="Sort in ascending order"),
):
    """
    Fetch all roles from the database along with their associated permissions.

    Args:

        limit (int, optional): The number of records to return. Defaults to None.
        order_by (str, optional): The column to order the results by. Defaults to role_id.
        ascending (bool, optional): Sort in ascending order. Defaults to True.
        Note: the allowed columns are "role_id", "name", and "description".
    Returns:

        list[Role]: A list of Role objects with their associated permissions.
    Raises:

        HTTPException: If an integrity error or any other database error occurs,
                       an HTTPException is raised with an appropriate status code
                       and error message.
    """

    try:
        allowed_columns = [
            "role_id",
            "name",
            "description",
        ]  # Add valid column names here

        # Start building the query
        stmt = select(Role)

        # Apply ordering
        # Validate and set the order_by column or a default value
        if order_by is None:
            order_by = "role_id"
        order_by = (
            order_by.lower() if order_by.lower() in allowed_columns else "role_id"
        )
        order_column = getattr(Role, order_by)
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
        logging.error(f"Integrity error occurred: {str(e.orig)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching all roles.",
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching all roles.",
        )


@router.get(
    "/{role_id}",
    response_model=RoleReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            check_permissions(["manage_roles_AUTH_SERVICE", "view_roles_AUTH_SERVICE"])
        )
    ],
)
def read_role(db: db_dependency, role_id: int = Path(gt=0)):
    """
    Fetch a role by its ID from the database.
    Args:

        role_id (int): The ID of the role to fetch. Must be greater than 0.
    Returns:

        Role: The role object if found.
    Raises:

        HTTPException: If the role is not found, or if there is an integrity error,
                       database error, or any other unexpected error.
    """

    try:
        stmt = select(Role).where(Role.role_id == role_id)
        role_model = db.execute(stmt).scalars().first()

        if role_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"role with id {role_id} not found.",
            )

        return role_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while fetching the role with id {role_id}.",
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
            detail=f"An error occurred while fetching the role with id {role_id}.",
        )


@router.put(
    "/{role_id}",
    response_model=RoleReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(check_permissions(["manage_roles_AUTH_SERVICE"]))],
)
def update_role(
    db: db_dependency, role_request: RoleUpdateRequest, role_id: int = Path(gt=0)
):
    """
    Update an existing role in the database.
    Args:

        role_request (RoleUpdateRequest): The request object containing the fields to update.
        - name (str): The name of the role.
        - description (str): The description of the role.
        role_id (int): The ID of the role to update. Must be greater than 0.
    Returns:

        role_model: The updated role model.
    Raises:

        HTTPException: If the role is not found, or if there is an integrity error,
                       database error, or any other unexpected error.
    """

    try:
        stmt = select(Role).where(Role.role_id == role_id)
        role_model = db.execute(stmt).scalars().first()

        if role_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"role with id {role_id} not found.",
            )

        # Loop through provided fields and update the corresponding fields in role_model
        update_data = role_request.model_dump(
            exclude_unset=True
        )  # Only get the provided fields

        for key, value in update_data.items():
            setattr(role_model, key, value)  # Dynamically update the fields

        db.commit()
        db.refresh(role_model)  # Refresh the updated instance
        return role_model  # Return the updated role model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the role with id {role_id}.",
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
            detail=f"An error occurred while updating the role with id {role_id}.",
        )


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(check_permissions(["manage_roles_AUTH_SERVICE"]))],
)
def delete_role(db: db_dependency, role_id: int = Path(gt=0)):
    """
    Delete a role from the database by its ID.
    Args:

        role_id (int): The ID of the role to delete. Must be greater than 0.
    Raises:

        HTTPException: If the role is not found, or if there is an integrity error,
                       database error, or any other unexpected error.
    Returns:

        None
    """

    try:
        stmt = select(Role).where(Role.role_id == role_id)
        role_model = db.execute(stmt).scalars().first()
        if role_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"role with id {role_id} not found.",
            )

        stmt = delete(Role).where(Role.role_id == role_id)
        db.execute(stmt)
        db.commit()

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e.orig)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the role with id {role_id}.",
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
            detail=f"An error occurred while deleting the role with id {role_id}.",
        )


# Create a new APIRouter instance for Role-Permission Router: Specifically manages the relationships between roles and permissions, allowing you to assign and revoke permissions from roles.
role_permission = APIRouter(prefix="/roles/{role_id}/permissions", tags=["Roles"])


@role_permission.post(
    "/",
    response_model=RoleReadRequest,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_permissions(["manage_roles_AUTH_SERVICE"]))],
)
def assign_permissions(
    permissions_request: list[
        int
    ],  # Expect to receive a list of permission ids not yet assigned to this role
    db: db_dependency,
    role_id: int = Path(gt=0),
):
    """
    Assigns a list of permissions to a role.
    Args:

        permissions_request (list[int]): A list of permission IDs to be assigned to the role.
        role_id (int): The ID of the role to which permissions will be assigned.
    Returns:

        Role: The updated role model with the newly assigned permissions.
    Raises:

        HTTPException: If the role is not found, if one or more permissions are not found,
                       if there is an integrity error, or if any other database error occurs.
    """

    try:
        stmt = select(Role).where(Role.role_id == role_id)
        role_model = db.execute(stmt).scalars().first()

        if role_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"role with id {role_id} not found.",
            )

        # Verify if any permission to be added is not existing in the Permission table
        stmt = select(Permission).where(
            Permission.permission_id.in_(permissions_request)
        )
        existing_permissions = db.execute(stmt).scalars().all()
        if len(existing_permissions) != len(permissions_request):
            # Initialize a new list of type integer to store non-matching permission IDs
            not_existing_permission_ids: list[int] = []

            # Loop through each permission ID in permissions_request
            for permission_id in permissions_request:
                # Check if the permission ID is not in the list of existing permission IDs
                if not any(
                    permission_id == permission.permission_id
                    for permission in existing_permissions
                ):
                    # Add to the new list if it doesn't exist in existing_permissions
                    not_existing_permission_ids.append(permission_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"One or more permissions not found: {not_existing_permission_ids}",
            )

        # Assign the permission to the role
        for perm in existing_permissions:
            if perm not in role_model.permissions:
                # print(perm.permission_id)
                # this auto maps the models then add records to RolePermission table
                role_model.permissions.append(perm)
        db.commit()
        db.refresh(role_model)  # Refresh the new instance
        return role_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while assigning permissions to the role with id {role_id}.",
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
            detail=f"An error occurred while assigning permissions to the role with id {role_id}.",
        )


@role_permission.delete(
    "/",
    response_model=RoleReadRequest,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(check_permissions(["manage_roles_AUTH_SERVICE"]))],
)
def revoke_permissions(
    permissions_request: list[
        int
    ],  # Expect to receive a list of permission ids not yet assigned to this role
    db: db_dependency,
    role_id: int = Path(gt=0),
):
    """
    Revoke specified permissions from a role.
    Args:

        permissions_request (list[int]): A list of permission IDs to be revoked from the role.
        role_id (int): The ID of the role from which permissions are to be revoked. Must be greater than 0.
    Returns:

        Role: The updated role model with the specified permissions revoked.
    Raises:

        HTTPException: If the role is not found, if one or more permissions are not found,
                       if there is an integrity error, or if any other database error occurs.
    """

    try:
        stmt = select(Role).where(Role.role_id == role_id)
        role_model = db.execute(stmt).scalars().first()

        if role_model is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"role with id {role_id} not found.",
            )

        # Verify if any permission to be removed is not existing in the Permission table
        stmt = select(Permission).where(
            Permission.permission_id.in_(permissions_request)
        )
        existing_permissions = db.execute(stmt).scalars().all()
        if len(existing_permissions) != len(permissions_request):
            # Initialize a new list of type integer to store non-matching permission IDs
            not_existing_permission_ids: list[int] = []

            # Loop through each permission ID in permissions_request
            for permission_id in permissions_request:
                # Check if the permission ID is not in the list of existing permission IDs
                if not any(
                    permission_id == permission.permission_id
                    for permission in existing_permissions
                ):
                    # Add to the new list if it doesn't exist in existing_permissions
                    not_existing_permission_ids.append(permission_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"One or more permissions not found: {not_existing_permission_ids}",
            )

        # Revoke the permission to the role
        for perm in existing_permissions:
            if perm in role_model.permissions:
                # print(perm.permission_id)
                # this auto maps the models then add records to RolePermission table
                role_model.permissions.remove(perm)
        db.commit()
        db.refresh(role_model)  # Refresh the new instance
        return role_model

    except IntegrityError as e:
        logging.error(f"Integrity error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.orig))
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while revoking permissions from the role with id {role_id}.",
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
            detail=f"An error occurred while revoking permissions from the role with id {role_id}.",
        )

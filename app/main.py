from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.base import Base
from app.db.base import engine
from app.api.v1 import (
    users,
    roles,
    permissions,
    auth,
)
from app.core.config import settings
import os

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description=settings.PROJECT_DESCRIPTION,
)

# Allow requests from the different services
origins = [
    os.getenv("AUTH_SERVICE_BASE_URL", "http://localhost:8001"),
    os.getenv("INVENTORY_SERVICE_BASE_URL", "http://localhost:8002"),
    os.getenv("ORDER_SERVICE_BASE_URL", "http://localhost:8003"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

if os.getenv("ENV") != "test":
    Base.metadata.create_all(bind=engine)


@app.get("/")
def index():
    return {"message": "AUTH-SERVICE MICROSERVICE API"}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(users.user_role)
app.include_router(roles.router)
app.include_router(roles.role_permission)
app.include_router(permissions.router)

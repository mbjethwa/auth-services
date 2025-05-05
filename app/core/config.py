import os
from pydantic_settings import BaseSettings
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer


class Settings(BaseSettings):
    # Project name and version
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "AUTH-SERVICE")
    PROJECT_VERSION: str = os.getenv("PROJECT_VERSION", "1.0.0")
    PROJECT_DESCRIPTION: str = os.getenv(
        "PROJECT_DESCRIPTION", "AUTH-SERVICE MICROSERVICE API"
    )
    # Configuration for JWT - This should be unique and random - For production and security, this should be stored securely in hard-coded in code base. Need to be unique - Can generate random with `openssl rand -hex 32`
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")  # type: ignore
    if not JWT_SECRET_KEY:
        raise ValueError("Missing JWT_SECRET_KEY environment variable!")

    ALGORITHM: str = "HS256"

    # Configuration for access token
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ACCESS_TOKEN_EXPIRE_DAYS_WITH_REMEMBER_ME: int = 7
    ACCESS_TOKEN_TYPE: str = "bearer"

    # Configuration for password hashing
    BCRYPT_SCHEMES: list[str] = ["bcrypt"]
    DEPRECATED: str = "auto"

    # You can create the instances outside the class
    @property
    def bcrypt_context(self) -> CryptContext:
        return CryptContext(schemes=self.BCRYPT_SCHEMES, deprecated=self.DEPRECATED)

    @property
    def oauth2_bearer(self) -> OAuth2PasswordBearer:
        return OAuth2PasswordBearer(tokenUrl="auth/token")

    # DB Connection for PostgreSQL
    # Use the environment variables for PostgreSQL connection details
    if os.getenv("ENV") != "test":
        POSTGRES_USER: str = os.getenv("POSTGRES_USER")
        POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
        POSTGRES_DB: str = os.getenv("POSTGRES_DB")
        POSTGRES_HOST: str = os.getenv("POSTGRES_HOST")  # Default to localhost
        POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", 5432))  # Convert port to int
        if not POSTGRES_USER:
            raise ValueError("Missing POSTGRES_USER environment variable!")
        if not POSTGRES_DB:
            raise ValueError("Missing POSTGRES_DB environment variable!")
        if not POSTGRES_HOST:
            raise ValueError("Missing POSTGRES_HOST environment variable!")
        if not POSTGRES_PORT:
            raise ValueError("Missing POSTGRES_PORT environment variable!")
        if not POSTGRES_PASSWORD:
            raise ValueError("Missing POSTGRES_PASSWORD environment variable!")

    # Create a connection string for PostgreSQL
    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        if os.getenv("ENV") == "test":
            return "sqlite:///:memory:"
        # Use environment variables for PostgreSQL connection details
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # DB Connection for SQLite for local development
    # @computed_field
    # @property
    # def SQLALCHEMY_DATABASE_URL(self) -> str:
    #     return "sqlite:///./app.db"


settings = Settings()

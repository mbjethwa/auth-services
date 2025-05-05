# Inside app/db/base.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from app.core.config import settings

# SQLALCHEMY_DATABASE_URL = 'sqlite:///./app.db'
SQLALCHEMY_DATABASE_URL = str(settings.SQLALCHEMY_DATABASE_URL)
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class to create models
Base = declarative_base()


# Dependency that will be used in the FastAPI routes to get a session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

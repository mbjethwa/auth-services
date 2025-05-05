#!/bin/sh

# Run Alembic migrations
alembic upgrade head

# Start the Uvicorn server
uvicorn app.main:app --host 0.0.0.0 --port 8000
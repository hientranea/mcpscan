#!/bin/bash
set -e

# Wait for database to be ready
echo "Waiting for database..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 0.5
done
echo "Database is ready!"

# Run migrations
echo "Running database migrations..."
cd /app
alembic upgrade head
echo "Migrations completed successfully!"

# Start the API server
echo "Starting API server..."
exec uvicorn api.main:app --host $API_HOST --port $API_PORT $@

#!/bin/bash

# Run the API service container with SQLite persistence
docker run --rm -p 6000:6000 \
  -v "$(pwd)/results:/app/results" \
  -v "$(pwd)/data:/app/data" \
  --name mcpscan-api \
  mcpscan-api

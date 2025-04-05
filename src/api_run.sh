#!/bin/bash

# Run the API service container
docker run --rm -p 5123:5123   \
  -v "$(pwd)/results:/app/results" \
  --name mcpscan-api \
  mcpscan-api

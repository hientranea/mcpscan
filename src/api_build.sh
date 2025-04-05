#!/bin/bash

# Build the base MCPScan image if it doesn't exist
if [[ "$(docker images -q mcpscan 2> /dev/null)" == "" ]]; then
  echo "Building base MCPScan image..."
  ./docker_build.sh
fi

# Build the API service image
echo "Building MCPScan API service image..."
docker build -t mcpscan-api -f api/Dockerfile .

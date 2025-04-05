# MSeeP Scanner

A security scanning and trust scoring system for MCP (Model Context Protocol) packages.

## Overview

MCP Scanner is a robust security analysis tool designed to evaluate GitHub repositories, particularly those containing MCP packages. It performs comprehensive security scans including static code analysis and dependency vulnerability assessment to calculate a trust score for each package.

The system consists of two main components:

- **API Service**: A FastAPI-based REST API for submitting scan requests and retrieving results
- **Scanner Service**: A background service that performs the actual scanning and analysis

## Features

- **Repository Analysis**: Clone and analyze GitHub repositories
- **Static Code Analysis**: Detect potentially dangerous code patterns using Semgrep
- **Dependency Scanning**: Identify vulnerabilities in npm and pip dependencies
- **Trust Scoring**: Calculate a security score based on findings

## Architecture

The system uses a microservices architecture with the following components:

- **API Service**: Handles HTTP requests and responses
- **Scanner Service**: Performs security analysis
- **Redis**: Used for job queuing and result storage
- **Docker**: Containerization for easy deployment

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Git

### Installation

1. Clone the repository:

   ```bash
   git clone github_url
   cd mcpscan
   ```

2. Build and start the services:

   ```bash
   docker-compose build
   docker-compose up -d
   ```

3. Verify the services are running:
   ```bash
   docker-compose ps
   ```

### Usage

#### Starting a Scan

To start a scan, send a POST request to the `/api/scan` endpoint:

```bash
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/username/repository"}'
```

Response:

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Scan job queued successfully"
}
```

#### Checking Scan Results

To check the status and results of a scan, send a GET request to the `/api/scan/{job_id}` endpoint:

```bash
curl http://localhost:8000/api/scan/550e8400-e29b-41d4-a716-446655440000
```

#### API Documentation

FastAPI provides automatic API documentation. You can access it at:

```
http://localhost:8000/docs
```

## Project Structure

```
mcpscan/
├── api/                  # API service
│   ├── main.py           # FastAPI application
│   ├── models.py         # Pydantic models
│   ├── routers/          # API routes
│   └── services/         # API services
├── scanner/              # Scanner service
│   ├── analyzers/        # Code analyzers
│   ├── rules/            # Semgrep rules
│   ├── services/         # Scanner services
│   └── main.py           # Scanner entry point
├── shared/               # Shared code
│   ├── config.py         # Configuration
│   ├── db/               # Database clients
│   ├── models.py         # Shared data models
│   └── utils/            # Utility functions
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile.api        # API Dockerfile
└── Dockerfile.scanner    # Scanner Dockerfile
```

### Adding New Analyzers

To add a new analyzer:

1. Create a new file in `scanner/analyzers/` that extends the `BaseAnalyzer` class
2. Implement the `analyze` method
3. Update the `ScanService` class to use your new analyzer

Example:

```python
from scanner.analyzers.base_analyzer import BaseAnalyzer

class MyNewAnalyzer(BaseAnalyzer):
    def analyze(self, working_dir):
        # Implement your analysis logic
        return {
            "results": [],
            "errors": []
        }
```

### Adding New Semgrep Rules

To add new Semgrep rules:

1. Create a new YAML file in `scanner/rules/semgrep/`
2. Define your rules following the Semgrep format
3. The scanner will automatically pick up and use the new rules

Example rule file:

```yaml
rules:
  - id: my-new-rule
    pattern: dangerous_function(...)
    message: "Use of dangerous_function detected"
    languages: [python]
    severity: WARNING
```

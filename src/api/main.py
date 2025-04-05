import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import scan
from shared.config import settings
from shared.utils.logging import setup_logging

# Setup logging
logger = setup_logging(service_name="api")

# Create FastAPI app
app = FastAPI(
    title="MCP Scanner API",
    description="API for scanning MCP packages and calculating trust scores",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    logger.info(f"Starting API server on {settings.API_HOST}:{settings.API_PORT}")
    uvicorn.run(
        "api.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=False
    )

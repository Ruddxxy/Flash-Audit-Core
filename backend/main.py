"""
FlashAudit Backend - FastAPI Application

Security-hardened API for ingesting scan findings and syncing state.
Implements authentication, rate limiting, and strict input validation.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import init_db, close_db
from models import (
    ErrorResponse,
    HealthResponse,
)

# =============================================================================
# Configuration
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("flashaudit")


# =============================================================================
# Application Lifecycle
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("Starting FlashAudit Backend...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down FlashAudit Backend...")
    await close_db()


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="FlashAudit Backend",
    description="Security-hardened API for secrets scanning findings",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
)

# CORS configuration (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Authorization", "Content-Type"],
)


# =============================================================================
# Exception Handlers
# =============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler with consistent error format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail).model_dump(),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler to prevent information leakage."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(error="Internal server error").model_dump(),
    )


# =============================================================================
# Health Check (No Auth)
# =============================================================================


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check endpoint",
)
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return HealthResponse()


# =============================================================================
# Modular Routers
# =============================================================================
# Every endpoint except /health lives in the routers/ package (auth, findings,
# repositories, analytics, settings, exports, cli). Mount them here so the app
# serves them.
from routers import (  # noqa: E402  (imported after app is defined)
    analytics,
    auth,
    cli,
    exports,
    findings,
    repositories,
    settings,
)

for _router_module in (auth, findings, repositories, analytics, settings, exports, cli):
    app.include_router(_router_module.router)


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
        log_level=LOG_LEVEL.lower(),
    )

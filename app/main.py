from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import settings
from app.api.api_v1.api import api_router
from app.core.scheduler import scheduler

app = FastAPI(
    title="AI-Powered Cyber Threat Detector",
    description="Real-time threat detection and analysis system",
    version="1.0.0",
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)

# Include API router
app.include_router(api_router, prefix="/api/v1")

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    scheduler.start()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    scheduler.shutdown()

@app.get("/")
async def root():
    return {
        "message": "Welcome to AI-Powered Cyber Threat Detector API",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    } 
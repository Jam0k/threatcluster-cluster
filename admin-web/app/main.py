"""
ThreatCluster Admin Panel
"""
import sys
import os
from pathlib import Path

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from app.core.config import settings
from app.core.auth import setup_oauth, oauth, is_authenticated, is_admin

# Import shared templates early
from app.core.templates import templates


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    print(f"Starting {settings.APP_NAME} on {settings.HOST}:{settings.PORT}")
    
    # Start scheduler
    from app.core.scheduler import scheduler
    await scheduler.start()
    
    yield
    
    # Shutdown
    print("Shutting down...")
    await scheduler.stop()


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie=settings.SESSION_COOKIE_NAME,
    same_site="lax",
    https_only=False,  # Set to True in production with HTTPS
    max_age=3600  # 1 hour session timeout
)

# Setup OAuth
setup_oauth(app)

# Check for required Auth0 configuration
print(f"Auth0 Domain: {settings.AUTH0_DOMAIN}")
print(f"Auth0 Client ID: {settings.AUTH0_CLIENT_ID}")
print(f"Auth0 Client Secret: {'*' * len(settings.AUTH0_CLIENT_SECRET) if settings.AUTH0_CLIENT_SECRET else 'NOT SET'}")
print(f"Auth0 Callback URL: {settings.AUTH0_CALLBACK_URL}")

if not settings.AUTH0_CLIENT_SECRET:
    print("WARNING: AUTH0_CLIENT_SECRET is not set. OAuth login will not work properly.")
    print("Please set AUTH0_CLIENT_SECRET in your .env file or environment variables.")

# Mount static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Import shared templates and add globals
from app.core.templates import templates
templates.env.globals["app_name"] = settings.APP_NAME
templates.env.globals["is_authenticated"] = is_authenticated
templates.env.globals["is_admin"] = is_admin


# Add external paths for route imports that need cluster modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Import routers after path setup
from app.routes import auth, dashboard, pipeline, monitoring, entities, maintenance, scheduler

# Include routers
app.include_router(auth.router, tags=["auth"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
app.include_router(pipeline.router, prefix="/pipeline", tags=["pipeline"])
app.include_router(monitoring.router, prefix="/monitoring", tags=["monitoring"])
app.include_router(entities.router, prefix="/entities", tags=["entities"])
app.include_router(maintenance.router, prefix="/maintenance", tags=["maintenance"])
app.include_router(scheduler.router, prefix="/scheduler", tags=["scheduler"])


@app.get("/")
async def root(request: Request):
    """Root route - redirect to dashboard or login"""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": settings.APP_NAME, "version": settings.APP_VERSION}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
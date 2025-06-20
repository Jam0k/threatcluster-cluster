"""
Configuration for ThreatCluster Admin Panel
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings

# Debug environment (only in development)
if os.environ.get('DEBUG'):
    print("=== Environment Variables ===")
    print(f"DATABASE_URL from env: {os.environ.get('DATABASE_URL', 'NOT SET')}")
    print(f"AUTH0_DOMAIN from env: {os.environ.get('AUTH0_DOMAIN', 'NOT SET')}")
    print(f"Working directory: {os.getcwd()}")
    print("==============================")



class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ThreatCluster Admin"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Server
    HOST: str = "localhost"
    PORT: int = 8002
    
    # Auth0
    AUTH0_DOMAIN: str = "dev-mazc2h57lknel3yr.uk.auth0.com"
    AUTH0_CLIENT_ID: str = "KLzhVYbuDcfG7I08XgBGu4wW0V5XVZla"
    AUTH0_CLIENT_SECRET: str = ""
    AUTH0_CALLBACK_URL: str = "http://localhost:8002/callback"
    
    # Session
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    SESSION_COOKIE_NAME: str = "threatcluster_admin_session"
    
    # Database
    DATABASE_URL: str = "postgresql://cluster_user:cluster_password@localhost:5432/cluster"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    CLUSTER_DIR: str = os.path.dirname(BASE_DIR)
    
    # Admin settings
    ADMIN_ROLE: str = "admin"
    SUPER_ADMIN_ROLE: str = "super-admin"
    
    # Pipeline settings
    PIPELINE_TIMEOUT: int = 3600  # 1 hour
    MAX_CONCURRENT_OPERATIONS: int = 1
    
    class Config:
        # Load .env from cluster directory (when running locally)
        # In Docker, environment variables come from docker-compose
        env_file = "../../.env" if not os.environ.get('DOCKER_CONTAINER') else None
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields in .env file


settings = Settings()
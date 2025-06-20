"""
Auth0 authentication for admin panel
"""
import json
from functools import wraps
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import HTTPException, Request
from jose import jwt
from starlette.responses import RedirectResponse

from .config import settings


# OAuth setup
oauth = None


def setup_oauth(app):
    """Initialize OAuth with Auth0"""
    global oauth
    # Initialize OAuth without app (we'll pass request in routes)
    oauth = OAuth()
    
    # Configure OAuth with Auth0
    oauth.register(
        "auth0",
        client_id=settings.AUTH0_CLIENT_ID,
        client_secret=settings.AUTH0_CLIENT_SECRET,
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
    )


class AuthError(Exception):
    """Auth error exception"""
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """Get current user from session"""
    return request.session.get("user")


def is_authenticated(request: Request) -> bool:
    """Check if user is authenticated"""
    return get_current_user(request) is not None


def is_admin(request: Request) -> bool:
    """Check if user has admin role"""
    user = get_current_user(request)
    if not user:
        return False
    
    roles = user.get("roles", [])
    return settings.ADMIN_ROLE in roles or settings.SUPER_ADMIN_ROLE in roles


def require_admin(request: Request) -> Dict[str, Any]:
    """Require admin authentication"""
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    return get_current_user(request)


def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    async def decorated_function(request: Request, *args, **kwargs):
        if not is_authenticated(request):
            # Redirect to login
            return RedirectResponse(url="/login", status_code=302)
        
        if not is_admin(request):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Add user to kwargs
        kwargs['current_user'] = get_current_user(request)
        return await f(request, *args, **kwargs)
    
    return decorated_function


async def get_user_info(token: str) -> Dict[str, Any]:
    """Get user info from Auth0"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://{settings.AUTH0_DOMAIN}/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            raise AuthError("Failed to get user info", response.status_code)
        
        return response.json()


def create_logout_url(return_to: str) -> str:
    """Create Auth0 logout URL"""
    params = {
        "returnTo": return_to,
        "client_id": settings.AUTH0_CLIENT_ID,
    }
    return f"https://{settings.AUTH0_DOMAIN}/v2/logout?" + urlencode(params)
"""
Authentication routes
"""
from fastapi import APIRouter, Request, HTTPException
from starlette.responses import RedirectResponse
from app.core.auth import get_user_info, create_logout_url, is_authenticated
from app.core import auth as auth_module
from app.core.config import settings
from app.core.templates import templates

router = APIRouter()


@router.get("/login")
async def login(request: Request):
    """Show login page"""
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@router.get("/auth/login")
async def auth_login(request: Request):
    """Initiate Auth0 login"""
    # Use the same pattern as frontend - build redirect URI from request
    redirect_uri = str(request.url_for("callback"))
    
    # Ensure it uses the correct scheme and port
    if "localhost" in redirect_uri:
        redirect_uri = redirect_uri.replace("http://", "http://")
        if ":8002" not in redirect_uri:
            redirect_uri = redirect_uri.replace("/callback", ":8002/callback")
    
    print(f"Redirect URI: {redirect_uri}")
    
    try:
        # Simple authorize redirect
        return await auth_module.oauth.auth0.authorize_redirect(request, redirect_uri)
    except Exception as e:
        print(f"Error in auth_login: {e}")
        import traceback
        traceback.print_exc()
        raise


@router.get("/callback", name="callback")
async def callback(request: Request):
    """Handle Auth0 callback"""
    try:
        # Debug: print session, cookies and query params
        print(f"Session data: {dict(request.session)}")
        print(f"Cookies: {dict(request.cookies)}")
        print(f"Query params: {dict(request.query_params)}")
        print(f"Headers: {dict(request.headers)}")
        
        token = await auth_module.oauth.auth0.authorize_access_token(request)
        
        # Get user info
        user_info = await get_user_info(token["access_token"])
        
        # Check for admin role
        roles = user_info.get("https://threatcluster.io/roles", [])
        if not roles:
            # Try alternative claim locations
            roles = user_info.get("roles", [])
        
        if settings.ADMIN_ROLE not in roles and settings.SUPER_ADMIN_ROLE not in roles:
            # Not an admin, show error
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "Access Denied",
                    "message": "You must have admin privileges to access this panel."
                }
            )
        
        # Store user in session
        request.session["user"] = {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "picture": user_info.get("picture"),
            "sub": user_info.get("sub"),
            "roles": roles,
            "token": token
        }
        
        return RedirectResponse(url="/dashboard", status_code=302)
        
    except Exception as e:
        print(f"Auth error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/logout")
async def logout(request: Request):
    """Logout user"""
    request.session.clear()
    return_to = str(request.base_url)
    logout_url = create_logout_url(return_to)
    return RedirectResponse(url=logout_url, status_code=302)
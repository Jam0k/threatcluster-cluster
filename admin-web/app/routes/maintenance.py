"""
Maintenance routes
"""
from fastapi import APIRouter, Request
from app.core.auth import admin_required
from app.core.templates import templates

router = APIRouter()


@router.get("/")
@admin_required
async def maintenance(request: Request, current_user: dict = None):
    """Maintenance page"""
    return templates.TemplateResponse(
        "maintenance.html",
        {"request": request, "user": current_user}
    )
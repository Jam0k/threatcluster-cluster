"""
Monitoring routes
"""
from fastapi import APIRouter, Request
from app.core.auth import admin_required
from app.core.templates import templates

router = APIRouter()


@router.get("/")
@admin_required
async def monitoring(request: Request, current_user: dict = None):
    """Monitoring page"""
    return templates.TemplateResponse(
        "monitoring.html",
        {"request": request, "user": current_user}
    )
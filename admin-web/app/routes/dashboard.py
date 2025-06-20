"""
Dashboard routes
"""
from fastapi import APIRouter, Request, Depends
from sqlalchemy import text
from datetime import datetime, timedelta

from app.core.auth import admin_required
from app.core.templates import templates
from app.core.database import db_manager

router = APIRouter()


@router.get("/")
@admin_required
async def dashboard(request: Request, current_user: dict = None):
    """Show admin dashboard"""
    # Get system statistics
    with db_manager.session() as session:
        stats = get_system_stats(session)
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": current_user,
            "stats": stats,
            "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    )


def get_system_stats(session):
    """Get current system statistics"""
    stats = {}
    
    # Last run time
    try:
        result = session.execute(text("""
            SELECT completed_at 
            FROM cluster.processing_runs 
            WHERE status = 'completed' 
            ORDER BY completed_at DESC 
            LIMIT 1
        """)).fetchone()
        
        if result and result.completed_at:
            stats['last_run'] = result.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            stats['last_run'] = "Never"
    except:
        stats['last_run'] = "Unknown"
    
    # Article stats (24h)
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as total,
                   COUNT(CASE WHEN processed_at IS NOT NULL THEN 1 END) as processed
            FROM cluster.articles
            WHERE fetched_at > NOW() - INTERVAL '24 hours'
        """)).fetchone()
        
        stats['articles_24h'] = result.total if result else 0
        stats['processed_24h'] = result.processed if result else 0
    except:
        stats['articles_24h'] = 0
        stats['processed_24h'] = 0
    
    # Active clusters
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as count
            FROM cluster.clusters
            WHERE is_active = TRUE
        """)).fetchone()
        
        stats['active_clusters'] = result.count if result else 0
    except:
        stats['active_clusters'] = 0
    
    # Total entities
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as count
            FROM cluster.entities
            WHERE is_predefined = TRUE OR occurrence_count > 5
        """)).fetchone()
        
        stats['total_entities'] = result.count if result else 0
    except:
        stats['total_entities'] = 0
    
    # Recent threats (7 days)
    try:
        result = session.execute(text("""
            SELECT COUNT(DISTINCT e.value) as count
            FROM cluster.entities e
            JOIN cluster.article_entities ae ON e.id = ae.entity_id
            JOIN cluster.articles a ON ae.article_id = a.id
            WHERE e.entity_type IN ('ransomware_group', 'apt_group', 'malware_family')
            AND a.fetched_at > NOW() - INTERVAL '7 days'
        """)).fetchone()
        
        stats['threats_7d'] = result.count if result else 0
    except:
        stats['threats_7d'] = 0
    
    # Pipeline health
    try:
        # Check for backlog
        backlog = session.execute(text("""
            SELECT COUNT(*) as count
            FROM cluster.articles
            WHERE processed_at IS NULL
            AND fetched_at < NOW() - INTERVAL '1 hour'
        """)).scalar()
        
        if backlog > 100:
            stats['pipeline_health'] = 'warning'
            stats['pipeline_message'] = f'{backlog} articles in backlog'
        else:
            stats['pipeline_health'] = 'healthy'
            stats['pipeline_message'] = 'All systems operational'
    except:
        stats['pipeline_health'] = 'unknown'
        stats['pipeline_message'] = 'Unable to determine status'
    
    return stats
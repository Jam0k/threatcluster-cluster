"""
Entity management routes
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy import func, text

from app.core.auth import admin_required
from app.core.templates import templates

# Import external modules - adjust paths since we're in cluster/admin-web
import sys
import os

# Add paths safely
cluster_path = os.path.join(os.path.dirname(__file__), '../../../')  # For cluster modules
if cluster_path not in sys.path:
    sys.path.append(cluster_path)

from app.core.database import db_manager

# Import models from admin-web models
from app.models.entity import Entity
from app.models.article import Article, ArticleEntity  
from app.models.cluster import Cluster, ClusterArticle, ClusterSharedEntity

router = APIRouter()


@router.get("/")
@admin_required
async def entities(request: Request, current_user: dict = None):
    """Entity management page"""
    
    try:
        with db_manager.session() as session:
            # Get entity statistics using the actual models
            total_entities = session.query(Entity).count()
            
            # Get counts by entity type
            type_counts = session.query(
                Entity.entity_type, 
                func.count(Entity.id)
            ).group_by(Entity.entity_type).all()
            
            type_dict = {entity_type: count for entity_type, count in type_counts}
            
            # Calculate IOC totals
            ioc_total = (type_dict.get('ip_address', 0) + 
                        type_dict.get('domain', 0) + 
                        type_dict.get('url', 0) + 
                        type_dict.get('file_hash', 0))
            
            stats = {
                'total_entities': total_entities,
                'threat_actors': type_dict.get('apt_group', 0) + type_dict.get('ransomware_group', 0),
                'malware': type_dict.get('malware_family', 0),
                'vulnerabilities': type_dict.get('cve', 0),
                'attack_patterns': type_dict.get('mitre_attack', 0) + type_dict.get('attack_type', 0),
                'tools': type_dict.get('platform', 0),
                'campaigns': type_dict.get('company', 0),
                'sectors': type_dict.get('industry', 0),
                'countries': ioc_total,  # Show IOCs in the last card with updated label
                'iocs': {
                    'ip_addresses': type_dict.get('ip_address', 0),
                    'domains': type_dict.get('domain', 0),
                    'urls': type_dict.get('url', 0),
                    'file_hashes': type_dict.get('file_hash', 0),
                    'total': ioc_total
                }
            }
            
            # Get top entities by occurrence using proper joins
            top_entities = session.query(
                Entity.value,
                Entity.entity_type,
                Entity.occurrence_count
            ).filter(
                Entity.occurrence_count > 0
            ).order_by(
                Entity.occurrence_count.desc()
            ).limit(15).all()
            
    except Exception as e:
        print(f"Error getting entity stats: {e}")
        import traceback
        traceback.print_exc()
        stats = {
            'total_entities': 0,
            'threat_actors': 0,
            'malware': 0,
            'vulnerabilities': 0,
            'attack_patterns': 0,
            'tools': 0,
            'campaigns': 0,
            'sectors': 0,
            'countries': 0,
        }
        top_entities = []
    
    return templates.TemplateResponse(
        "entities.html",
        {
            "request": request,
            "user": current_user,
            "stats": stats,
            "top_entities": top_entities
        }
    )


@router.post("/import/misp")
@admin_required
async def import_misp_galaxy(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Import MISP Galaxy threat actors"""
    task_id = f"misp_import_{datetime.utcnow().timestamp()}"
    
    background_tasks.add_task(run_misp_import, task_id, current_user)
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": "MISP Galaxy import started"
    })


@router.post("/import/mitre")
@admin_required
async def import_mitre_attack(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Import MITRE ATT&CK techniques"""
    task_id = f"mitre_import_{datetime.utcnow().timestamp()}"
    
    background_tasks.add_task(run_mitre_import, task_id, current_user)
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": "MITRE ATT&CK import started"
    })


@router.post("/import/iocs")
@admin_required
async def import_ioc_feeds(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Import all IOC feeds"""
    task_id = f"ioc_import_{datetime.utcnow().timestamp()}"
    
    background_tasks.add_task(run_ioc_import, task_id, current_user)
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": "IOC feeds import started"
    })


@router.post("/cleanup/iocs")
@admin_required
async def cleanup_old_iocs(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Cleanup old IOCs"""
    task_id = f"ioc_cleanup_{datetime.utcnow().timestamp()}"
    
    background_tasks.add_task(run_ioc_cleanup, task_id, current_user)
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": "IOC cleanup started"
    })


@router.post("/custom")
@admin_required
async def create_custom_entity(
    request: Request,
    current_user: dict = None
):
    """Create custom entity"""
    data = await request.json()
    
    try:
        with db_manager.session() as session:
            # Check if entity already exists
            existing = session.query(Entity).filter(
                Entity.value == data['name'],
                Entity.entity_type == data['type']
            ).first()
            
            if existing:
                raise HTTPException(status_code=400, detail="Entity already exists")
            
            # Create new entity
            entity = Entity(
                value=data['name'],
                entity_type=data['type'],
                is_predefined=False,
                occurrence_count=0,
                normalized_value=data['name'].lower(),
                metadata=data.get('metadata', {})
            )
            
            session.add(entity)
            session.commit()
            
            return JSONResponse({
                'id': entity.id,
                'name': entity.value,
                'type': entity.entity_type,
                'message': 'Entity created successfully'
            })
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating entity: {e}")
        raise HTTPException(status_code=500, detail="Failed to create entity")


@router.get("/search")
@admin_required
async def search_entities(
    request: Request,
    query: str = "",
    entity_type: str = None,
    limit: int = 50
):
    """Search entities"""
    try:
        with db_manager.session() as session:
            q = session.query(Entity)
            
            if query:
                q = q.filter(Entity.value.ilike(f"%{query}%"))
            
            if entity_type:
                q = q.filter(Entity.entity_type == entity_type)
            
            entities = q.order_by(Entity.occurrence_count.desc()).limit(limit).all()
            
            results = [{
                'id': e.id,
                'name': e.value,
                'type': e.entity_type,
                'occurrence_count': e.occurrence_count,
                'metadata': e.metadata
            } for e in entities]
            
        return JSONResponse(results)
    except Exception as e:
        print(f"Error searching entities: {e}")
        return JSONResponse([])


@router.delete("/{entity_id}")
@admin_required
async def delete_entity(
    request: Request,
    entity_id: int,
    current_user: dict = None
):
    """Delete an entity"""
    try:
        with db_manager.session() as session:
            entity = session.query(Entity).filter(Entity.id == entity_id).first()
            
            if not entity:
                raise HTTPException(status_code=404, detail="Entity not found")
            
            # Check if entity is being used in articles
            usage_count = session.query(ArticleEntity).filter(
                ArticleEntity.entity_id == entity_id
            ).count()
            
            if usage_count > 0:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Cannot delete entity. It is referenced in {usage_count} articles."
                )
            
            session.delete(entity)
            session.commit()
            
        return JSONResponse({"message": "Entity deleted successfully"})
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting entity: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete entity")


async def run_misp_import(task_id: str, user: dict):
    """Run MISP Galaxy import in background"""
    try:
        with db_manager.session() as session:
            # Import the MISP Galaxy importer from the CLI
            from cluster.core.misp_galaxy_importer import MISPGalaxyImporter
            
            importer = MISPGalaxyImporter(session)
            # Use the correct method name - import_all() for all entity types
            results = await importer.import_all()
            
            print(f"MISP import completed: {results}")
            
            # Get stats after import
            stats = importer.get_import_stats()
            print(f"MISP import stats: {stats}")
            
    except Exception as e:
        print(f"MISP import failed: {str(e)}")
        import traceback
        traceback.print_exc()


async def run_mitre_import(task_id: str, user: dict):
    """Run MITRE ATT&CK import in background"""
    try:
        with db_manager.session() as session:
            # Import the MITRE ATT&CK importer from the CLI
            from cluster.core.mitre_attack_importer import MITREAttackImporter
            
            importer = MITREAttackImporter(session)
            # Use the correct method name - import_techniques()
            results = await importer.import_techniques()
            
            print(f"MITRE import completed: {results}")
            
            # Get stats after import
            stats = importer.get_technique_stats()
            print(f"MITRE import stats: {stats}")
            
    except Exception as e:
        print(f"MITRE import failed: {str(e)}")
        import traceback
        traceback.print_exc()


async def run_ioc_import(task_id: str, user: dict):
    """Run IOC feeds import in background"""
    try:
        with db_manager.session() as session:
            # Import the IOC ingester from the CLI
            from cluster.core.ioc_ingester import IOCIngester
            from pathlib import Path
            
            # Get config path as Path object
            config_path = Path(__file__).parent.parent.parent.parent / 'core' / 'ioc_feeds.yaml'
            
            ingester = IOCIngester(session, config_path)
            # Use the main ingestion method
            results = await ingester.ingest_all_feeds()
            
            print(f"IOC import completed: {results}")
            
    except Exception as e:
        print(f"IOC import failed: {str(e)}")
        import traceback
        traceback.print_exc()


async def run_ioc_cleanup(task_id: str, user: dict):
    """Run IOC cleanup in background"""
    try:
        with db_manager.session() as session:
            # Import the IOC ingester from the CLI
            from cluster.core.ioc_ingester import IOCIngester
            from pathlib import Path
            
            # Get config path as Path object
            config_path = Path(__file__).parent.parent.parent.parent / 'core' / 'ioc_feeds.yaml'
            
            ingester = IOCIngester(session, config_path)
            # Cleanup IOCs older than 90 days
            results = ingester.cleanup_old_iocs(90)
            
            print(f"IOC cleanup completed: {results}")
            
    except Exception as e:
        print(f"IOC cleanup failed: {str(e)}")
        import traceback
        traceback.print_exc()
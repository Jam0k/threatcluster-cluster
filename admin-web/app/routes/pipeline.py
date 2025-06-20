"""
Pipeline control routes
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
import queue
import threading

from app.core.auth import admin_required
from app.core.config import settings
from app.core.templates import templates

# Add paths safely for cluster imports
import sys
import os
cluster_path = os.path.join(os.path.dirname(__file__), '../../../')
if cluster_path not in sys.path:
    sys.path.append(cluster_path)

from app.core.database import db_manager
from cluster.core.pipeline import create_pipeline

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# Store active pipeline tasks
active_tasks = {}

# Store log queues for each task
task_logs = {}


class TaskLogHandler(logging.Handler):
    """Custom log handler to capture logs for a specific task"""
    def __init__(self, task_id: str):
        super().__init__()
        self.task_id = task_id
        if task_id not in task_logs:
            task_logs[task_id] = queue.Queue()
    
    def emit(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': self.format(record),
            'module': record.module
        }
        task_logs[self.task_id].put(log_entry)


@router.get("/")
@admin_required
async def pipeline_control(request: Request, current_user: dict = None):
    """Pipeline control page"""
    return templates.TemplateResponse(
        "pipeline.html",
        {
            "request": request,
            "user": current_user,
            "active_tasks": list(active_tasks.keys())
        }
    )


@router.post("/run/full")
@admin_required
async def run_full_pipeline(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Run full pipeline"""
    task_id = f"full_pipeline_{datetime.utcnow().timestamp()}"
    
    if len(active_tasks) >= settings.MAX_CONCURRENT_OPERATIONS:
        raise HTTPException(status_code=429, detail="Too many concurrent operations")
    
    # Run pipeline in background
    background_tasks.add_task(run_pipeline_task, task_id, "full", current_user)
    active_tasks[task_id] = {"status": "starting", "type": "full"}
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": "Full pipeline started"
    })


@router.post("/run/{stage}")
@admin_required
async def run_pipeline_stage(
    request: Request,
    stage: str,
    background_tasks: BackgroundTasks,
    current_user: dict = None
):
    """Run specific pipeline stage"""
    valid_stages = ["feeds", "cluster", "entities", "rank"]
    if stage not in valid_stages:
        raise HTTPException(status_code=400, detail=f"Invalid stage. Must be one of: {valid_stages}")
    
    task_id = f"{stage}_{datetime.utcnow().timestamp()}"
    
    if len(active_tasks) >= settings.MAX_CONCURRENT_OPERATIONS:
        raise HTTPException(status_code=429, detail="Too many concurrent operations")
    
    # Run stage in background
    background_tasks.add_task(run_pipeline_task, task_id, stage, current_user)
    active_tasks[task_id] = {"status": "starting", "type": stage}
    
    return JSONResponse({
        "task_id": task_id,
        "status": "started",
        "message": f"{stage.title()} stage started"
    })


@router.get("/active")
async def get_active_tasks():
    """Get list of active task IDs"""
    return JSONResponse([
        task_id for task_id, task_info in active_tasks.items()
        if task_info.get("status") not in ["completed", "failed"]
    ])


@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """Get status of a pipeline task"""
    if task_id not in active_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return JSONResponse(active_tasks[task_id])


@router.get("/stream/{task_id}")
async def stream_task_progress(request: Request, task_id: str):
    """Stream task progress using Server-Sent Events"""
    if task_id not in active_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    async def event_generator():
        last_log_count = 0
        
        while task_id in active_tasks:
            task_info = active_tasks.get(task_id, {})
            
            # Get new logs
            logs = []
            if task_id in task_logs:
                log_queue = task_logs[task_id]
                while not log_queue.empty():
                    try:
                        logs.append(log_queue.get_nowait())
                    except queue.Empty:
                        break
            
            data = {
                "task_id": task_id,
                "status": task_info.get("status", "unknown"),
                "progress": task_info.get("progress", 0),
                "message": task_info.get("message", ""),
                "completed": task_info.get("status") in ["completed", "failed"],
                "logs": logs,
                "error": task_info.get("error", None)
            }
            
            yield {
                "data": json.dumps(data)
            }
            
            if task_info.get("status") in ["completed", "failed"]:
                break
                
            await asyncio.sleep(1)
    
    return EventSourceResponse(event_generator())


@router.get("/logs/{task_id}")
async def get_task_logs(task_id: str):
    """Get all logs for a specific task"""
    if task_id not in task_logs:
        raise HTTPException(status_code=404, detail="No logs found for this task")
    
    logs = []
    log_queue = task_logs[task_id]
    
    # Get all logs without removing them
    temp_logs = []
    while not log_queue.empty():
        try:
            log = log_queue.get_nowait()
            logs.append(log)
            temp_logs.append(log)
        except queue.Empty:
            break
    
    # Put logs back
    for log in temp_logs:
        log_queue.put(log)
    
    return JSONResponse({"task_id": task_id, "logs": logs})


async def run_pipeline_task(task_id: str, task_type: str, user: dict):
    """Run pipeline task in background"""
    # Set up logging for this task
    log_handler = TaskLogHandler(task_id)
    log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    
    # Add handler to all relevant loggers
    loggers = [
        logging.getLogger('cluster.core'),
        logging.getLogger('cluster.core.pipeline'),
        logging.getLogger('cluster.core.feed_collector'),
        logging.getLogger('cluster.core.semantic_clusterer'),
        logging.getLogger('cluster.core.entity_refresher'),
        logging.getLogger('cluster.core.ranker'),
        logging.getLogger(__name__)
    ]
    
    for logger_obj in loggers:
        logger_obj.addHandler(log_handler)
        logger_obj.setLevel(logging.INFO)
    
    try:
        # Initialize task if it doesn't exist (for scheduled tasks)
        if task_id not in active_tasks:
            active_tasks[task_id] = {
                "status": "starting",
                "type": task_type,
                "message": "Initializing...",
                "progress": 0
            }
            
        active_tasks[task_id]["status"] = "running"
        active_tasks[task_id]["started_at"] = datetime.utcnow().isoformat()
        active_tasks[task_id]["user"] = user.get("email") if user else "scheduler"
        
        logger.info(f"Starting {task_type} pipeline task for user {user.get('email') if user else 'scheduler'}")
        
        with db_manager.session() as session:
            pipeline = create_pipeline(session)
            
            if task_type == "full":
                # Run full pipeline
                active_tasks[task_id]["message"] = "Starting feed collection..."
                logger.info("Running full pipeline")
                results = pipeline.run_full_pipeline()
                
            elif task_type == "feeds":
                active_tasks[task_id]["message"] = "Collecting feeds..."
                logger.info("Collecting feeds")
                results = pipeline.feed_collector.collect_all_feeds()
                
            elif task_type == "cluster":
                active_tasks[task_id]["message"] = "Clustering articles..."
                logger.info("Clustering articles")
                results = pipeline.semantic_clusterer.cluster_articles()
                
            elif task_type == "entities":
                active_tasks[task_id]["message"] = "Refreshing entities..."
                logger.info("Refreshing entities")
                results = pipeline.entity_refresher.refresh_all_entities()
                
            elif task_type == "rank":
                active_tasks[task_id]["message"] = "Updating rankings..."
                logger.info("Updating rankings")
                results = pipeline.ranker.update_all_rankings()
            
            # Update task status
            active_tasks[task_id]["status"] = "completed"
            active_tasks[task_id]["completed_at"] = datetime.utcnow().isoformat()
            active_tasks[task_id]["results"] = results
            active_tasks[task_id]["message"] = "Task completed successfully"
            logger.info(f"Task {task_id} completed successfully")
            
    except Exception as e:
        logger.error(f"Task {task_id} failed: {str(e)}", exc_info=True)
        active_tasks[task_id]["status"] = "failed"
        active_tasks[task_id]["error"] = str(e)
        active_tasks[task_id]["message"] = f"Task failed: {str(e)}"
        active_tasks[task_id]["completed_at"] = datetime.utcnow().isoformat()
    finally:
        # Remove handlers
        for logger_obj in loggers:
            logger_obj.removeHandler(log_handler)
    
    # Clean up after 5 minutes
    await asyncio.sleep(300)
    if task_id in active_tasks:
        del active_tasks[task_id]
    if task_id in task_logs:
        del task_logs[task_id]
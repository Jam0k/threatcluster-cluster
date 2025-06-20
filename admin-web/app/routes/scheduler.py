"""
Scheduler management routes
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import func, desc

from app.core.auth import admin_required
from app.core.templates import templates
from app.core.scheduler import scheduler

# Add paths for cluster imports
import sys
import os
cluster_path = os.path.join(os.path.dirname(__file__), '../../../')
if cluster_path not in sys.path:
    sys.path.append(cluster_path)

from app.core.database import db_manager
from app.db_models.scheduled_task import ScheduledTask, ScheduledTaskRun

router = APIRouter()


def format_schedule(schedule_type: str, config: dict) -> str:
    """Format schedule configuration for display"""
    if schedule_type == 'daily':
        return f"Daily at {config.get('hour', 0)}:{str(config.get('minute', 0)).zfill(2)} UTC"
    elif schedule_type == 'weekly':
        days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        day_idx = config.get('day_of_week', 0)
        return f"Weekly on {days[day_idx]} at {config.get('hour', 0)}:{str(config.get('minute', 0)).zfill(2)} UTC"
    elif schedule_type == 'monthly':
        return f"Monthly on day {config.get('day', 1)} at {config.get('hour', 0)}:{str(config.get('minute', 0)).zfill(2)} UTC"
    elif schedule_type == 'interval':
        parts = []
        if config.get('weeks'):
            parts.append(f"{config['weeks']} weeks")
        if config.get('days'):
            parts.append(f"{config['days']} days")
        if config.get('hours'):
            parts.append(f"{config['hours']} hours")
        if config.get('minutes'):
            parts.append(f"{config['minutes']} minutes")
        return f"Every {', '.join(parts)}" if parts else "Invalid interval"
    elif schedule_type == 'cron':
        return f"Cron: {config}"
    return schedule_type


@router.get("/")
@admin_required
async def scheduler_page(request: Request, current_user: dict = None):
    """Scheduler management page"""
    
    try:
        with db_manager.session() as session:
            # Get all scheduled tasks
            tasks = session.query(ScheduledTask).order_by(ScheduledTask.name).all()
            
            # Get execution statistics
            stats = {
                'total_tasks': len(tasks),
                'enabled_tasks': sum(1 for t in tasks if t.enabled),
                'running_tasks': sum(1 for t in tasks if t.last_status == 'running'),
                'failed_tasks': sum(1 for t in tasks if t.last_status == 'failed'),
            }
            
            # Get recent runs
            recent_runs = session.query(ScheduledTaskRun).order_by(
                desc(ScheduledTaskRun.started_at)
            ).limit(20).all()
            
            # Format tasks for display
            task_list = []
            for task in tasks:
                task_info = {
                    'id': task.id,
                    'name': task.name,
                    'task_type': task.task_type,
                    'description': task.description,
                    'enabled': task.enabled,
                    'schedule_type': task.schedule_type,
                    'schedule_config': task.schedule_config,
                    'last_run': task.last_run,
                    'next_run': task.next_run,
                    'last_status': task.last_status,
                    'last_error': task.last_error,
                    'last_duration': task.last_duration_seconds,
                    'total_runs': task.total_runs,
                    'successful_runs': task.successful_runs,
                    'failed_runs': task.failed_runs,
                    'success_rate': round((task.successful_runs / task.total_runs * 100) if task.total_runs > 0 else 0, 1),
                    'schedule_display': format_schedule(task.schedule_type, task.schedule_config)
                }
                
                # Get active job status
                job_status = scheduler.get_task_status(task.id)
                if job_status:
                    task_info['is_scheduled'] = True
                    task_info['next_fire_time'] = job_status['next_run']
                else:
                    task_info['is_scheduled'] = False
                    
                task_list.append(task_info)
                
    except Exception as e:
        print(f"Error loading scheduler data: {e}")
        stats = {'total_tasks': 0, 'enabled_tasks': 0, 'running_tasks': 0, 'failed_tasks': 0}
        task_list = []
        recent_runs = []
        
    return templates.TemplateResponse(
        "scheduler.html",
        {
            "request": request,
            "user": current_user,
            "stats": stats,
            "tasks": task_list,
            "recent_runs": recent_runs
        }
    )


@router.post("/tasks")
@admin_required
async def create_task(request: Request, current_user: dict = None):
    """Create a new scheduled task"""
    data = await request.json()
    
    try:
        with db_manager.session() as session:
            # Check if task name already exists
            existing = session.query(ScheduledTask).filter(
                ScheduledTask.name == data['name']
            ).first()
            
            if existing:
                raise HTTPException(status_code=400, detail="Task name already exists")
                
            # Create new task
            task = ScheduledTask(
                name=data['name'],
                task_type=data['task_type'],
                description=data.get('description', ''),
                enabled=data.get('enabled', True),
                schedule_type=data['schedule_type'],
                schedule_config=data['schedule_config'],
                task_config=data.get('task_config', {})
            )
            
            session.add(task)
            session.commit()
            
            # Add to scheduler if enabled
            if task.enabled:
                await scheduler.add_task(task)
                
            return JSONResponse({
                'id': task.id,
                'message': 'Task created successfully'
            })
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/tasks/{task_id}")
@admin_required
async def update_task(request: Request, task_id: int, current_user: dict = None):
    """Update a scheduled task"""
    data = await request.json()
    
    try:
        with db_manager.session() as session:
            task = session.query(ScheduledTask).filter(
                ScheduledTask.id == task_id
            ).first()
            
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
                
            # Update fields
            if 'name' in data:
                task.name = data['name']
            if 'description' in data:
                task.description = data['description']
            if 'enabled' in data:
                task.enabled = data['enabled']
            if 'schedule_type' in data:
                task.schedule_type = data['schedule_type']
            if 'schedule_config' in data:
                task.schedule_config = data['schedule_config']
            if 'task_config' in data:
                task.task_config = data['task_config']
                
            task.updated_at = datetime.utcnow()
            session.commit()
            
            # Update scheduler
            await scheduler.update_task(task_id)
            
            return JSONResponse({'message': 'Task updated successfully'})
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tasks/{task_id}")
@admin_required
async def delete_task(request: Request, task_id: int, current_user: dict = None):
    """Delete a scheduled task"""
    try:
        with db_manager.session() as session:
            task = session.query(ScheduledTask).filter(
                ScheduledTask.id == task_id
            ).first()
            
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
                
            # Remove from scheduler
            await scheduler.remove_task(task_id)
            
            # Delete from database
            session.delete(task)
            session.commit()
            
            return JSONResponse({'message': 'Task deleted successfully'})
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/toggle")
@admin_required
async def toggle_task(request: Request, task_id: int, current_user: dict = None):
    """Enable/disable a scheduled task"""
    try:
        with db_manager.session() as session:
            task = session.query(ScheduledTask).filter(
                ScheduledTask.id == task_id
            ).first()
            
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
                
            # Toggle enabled status
            task.enabled = not task.enabled
            session.commit()
            
            # Update scheduler
            await scheduler.update_task(task_id)
            
            return JSONResponse({
                'enabled': task.enabled,
                'message': f"Task {'enabled' if task.enabled else 'disabled'} successfully"
            })
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error toggling task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/{task_id}/run")
@admin_required
async def run_task_now(request: Request, task_id: int, current_user: dict = None):
    """Run a task immediately"""
    try:
        with db_manager.session() as session:
            task = session.query(ScheduledTask).filter(
                ScheduledTask.id == task_id
            ).first()
            
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
                
        # Execute task asynchronously
        import asyncio
        asyncio.create_task(scheduler._execute_task(task_id))
        
        return JSONResponse({'message': 'Task execution started'})
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error running task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}/runs")
@admin_required
async def get_task_runs(
    request: Request, 
    task_id: int,
    limit: int = 50,
    current_user: dict = None
):
    """Get execution history for a task"""
    try:
        with db_manager.session() as session:
            runs = session.query(ScheduledTaskRun).filter(
                ScheduledTaskRun.task_id == task_id
            ).order_by(
                desc(ScheduledTaskRun.started_at)
            ).limit(limit).all()
            
            run_list = []
            for run in runs:
                run_list.append({
                    'id': run.id,
                    'started_at': run.started_at.isoformat(),
                    'completed_at': run.completed_at.isoformat() if run.completed_at else None,
                    'status': run.status,
                    'duration_seconds': run.duration_seconds,
                    'error_message': run.error_message,
                    'output': run.output
                })
                
        return JSONResponse(run_list)
        
    except Exception as e:
        print(f"Error getting task runs: {e}")
        return JSONResponse([])


@router.get("/stats")
@admin_required
async def get_scheduler_stats(request: Request, current_user: dict = None):
    """Get scheduler statistics"""
    try:
        with db_manager.session() as session:
            # Get task statistics
            total_tasks = session.query(func.count(ScheduledTask.id)).scalar()
            enabled_tasks = session.query(func.count(ScheduledTask.id)).filter(
                ScheduledTask.enabled == True
            ).scalar()
            
            # Get run statistics for last 24 hours
            yesterday = datetime.utcnow() - timedelta(days=1)
            recent_runs = session.query(
                ScheduledTaskRun.status,
                func.count(ScheduledTaskRun.id)
            ).filter(
                ScheduledTaskRun.started_at >= yesterday
            ).group_by(ScheduledTaskRun.status).all()
            
            run_stats = {status: count for status, count in recent_runs}
            
            # Get average duration by task type
            avg_durations = session.query(
                ScheduledTask.task_type,
                func.avg(ScheduledTaskRun.duration_seconds)
            ).join(
                ScheduledTaskRun, ScheduledTask.id == ScheduledTaskRun.task_id
            ).filter(
                ScheduledTaskRun.status == 'success'
            ).group_by(ScheduledTask.task_type).all()
            
            stats = {
                'total_tasks': total_tasks,
                'enabled_tasks': enabled_tasks,
                'runs_24h': {
                    'success': run_stats.get('success', 0),
                    'failed': run_stats.get('failed', 0),
                    'running': run_stats.get('running', 0)
                },
                'avg_duration_by_type': {
                    task_type: round(avg_duration or 0, 1) 
                    for task_type, avg_duration in avg_durations
                }
            }
            
        return JSONResponse(stats)
        
    except Exception as e:
        print(f"Error getting scheduler stats: {e}")
        return JSONResponse({
            'total_tasks': 0,
            'enabled_tasks': 0,
            'runs_24h': {'success': 0, 'failed': 0, 'running': 0},
            'avg_duration_by_type': {}
        })
"""
Background scheduler for automated tasks
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from sqlalchemy.orm import Session
import pytz

# Add paths for cluster imports
import sys
import os
cluster_path = os.path.join(os.path.dirname(__file__), '../../../')
if cluster_path not in sys.path:
    sys.path.append(cluster_path)

from app.core.database import db_manager
from app.db_models.scheduled_task import ScheduledTask, ScheduledTaskRun

logger = logging.getLogger(__name__)


class TaskScheduler:
    """Manages scheduled task execution"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler(timezone=pytz.UTC)
        self.active_tasks = {}
        
    async def start(self):
        """Start the scheduler and load tasks"""
        logger.info("Starting task scheduler...")
        self.scheduler.start()
        
        # Load all enabled tasks from database
        await self.reload_tasks()
        
    async def stop(self):
        """Stop the scheduler"""
        logger.info("Stopping task scheduler...")
        self.scheduler.shutdown()
        
    async def reload_tasks(self):
        """Reload all tasks from database"""
        try:
            with db_manager.session() as session:
                tasks = session.query(ScheduledTask).filter(
                    ScheduledTask.enabled == True
                ).all()
                
                # Remove all existing jobs
                self.scheduler.remove_all_jobs()
                self.active_tasks.clear()
                
                # Add jobs for each enabled task
                for task in tasks:
                    self._schedule_task(task)
                    
                logger.info(f"Loaded {len(tasks)} scheduled tasks")
                
        except Exception as e:
            logger.error(f"Failed to reload tasks: {e}")
            
    def _schedule_task(self, task: ScheduledTask):
        """Schedule a single task"""
        try:
            trigger = self._create_trigger(task)
            if trigger:
                job = self.scheduler.add_job(
                    self._execute_task,
                    trigger,
                    args=[task.id],
                    id=f"task_{task.id}",
                    name=task.name,
                    misfire_grace_time=300  # 5 minutes grace period
                )
                self.active_tasks[task.id] = job
                
                # Update next run time
                next_run = job.next_run_time
                if next_run:
                    with db_manager.session() as session:
                        db_task = session.query(ScheduledTask).filter(
                            ScheduledTask.id == task.id
                        ).first()
                        if db_task:
                            db_task.next_run = next_run
                            session.commit()
                            
                logger.info(f"Scheduled task '{task.name}' (ID: {task.id})")
                
        except Exception as e:
            logger.error(f"Failed to schedule task '{task.name}': {e}")
            
    def _create_trigger(self, task: ScheduledTask):
        """Create appropriate trigger based on schedule type"""
        try:
            config = task.schedule_config
            
            if task.schedule_type == 'cron':
                return CronTrigger(**config)
                
            elif task.schedule_type == 'interval':
                # Config should have: weeks, days, hours, minutes, seconds
                return IntervalTrigger(**config)
                
            elif task.schedule_type == 'daily':
                # Config should have: hour, minute
                hour = config.get('hour', 0)
                minute = config.get('minute', 0)
                return CronTrigger(hour=hour, minute=minute)
                
            elif task.schedule_type == 'weekly':
                # Config should have: day_of_week (0-6), hour, minute
                day = config.get('day_of_week', 0)
                hour = config.get('hour', 0)
                minute = config.get('minute', 0)
                return CronTrigger(day_of_week=day, hour=hour, minute=minute)
                
            elif task.schedule_type == 'monthly':
                # Config should have: day (1-31), hour, minute
                day = config.get('day', 1)
                hour = config.get('hour', 0)
                minute = config.get('minute', 0)
                return CronTrigger(day=day, hour=hour, minute=minute)
                
            else:
                logger.error(f"Unknown schedule type: {task.schedule_type}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create trigger for task '{task.name}': {e}")
            return None
            
    async def _execute_task(self, task_id: int):
        """Execute a scheduled task"""
        start_time = datetime.utcnow()
        run_id = None
        task_name = None
        task_type = None
        task_config = None
        
        try:
            # First session: Create run record and get task details
            with db_manager.session() as session:
                # Get task details
                task = session.query(ScheduledTask).filter(
                    ScheduledTask.id == task_id
                ).first()
                
                if not task:
                    logger.error(f"Task {task_id} not found")
                    return
                
                # Store task details before session closes
                task_name = task.name
                task_type = task.task_type
                task_config = task.task_config.copy() if task.task_config else {}
                    
                # Create run record
                task_run = ScheduledTaskRun(
                    task_id=task_id,
                    started_at=start_time,
                    status='running'
                )
                session.add(task_run)
                session.commit()
                run_id = task_run.id
                
                # Update task status
                task.last_run = start_time
                task.last_status = 'running'
                session.commit()
                
            logger.info(f"Executing task '{task_name}' (ID: {task_id})")
            
            # Execute based on task type
            output = await self._run_task_type_data(task_type, task_config, task_id)
            
            # Update success status
            end_time = datetime.utcnow()
            duration = int((end_time - start_time).total_seconds())
            
            with db_manager.session() as session:
                # Update run record
                if run_id:
                    task_run = session.query(ScheduledTaskRun).filter(
                        ScheduledTaskRun.id == run_id
                    ).first()
                    if task_run:
                        task_run.completed_at = end_time
                        task_run.status = 'success'
                        task_run.output = output
                        task_run.duration_seconds = duration
                    
                # Update task
                task = session.query(ScheduledTask).filter(
                    ScheduledTask.id == task_id
                ).first()
                if task:
                    task.last_status = 'success'
                    task.last_error = None
                    task.last_duration_seconds = duration
                    task.total_runs += 1
                    task.successful_runs += 1
                    
                    # Update next run time
                    job = self.active_tasks.get(task_id)
                    if job:
                        task.next_run = job.next_run_time
                        
                session.commit()
                
            logger.info(f"Task '{task_name}' completed successfully in {duration}s")
            
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
            
            # Update failure status
            end_time = datetime.utcnow()
            duration = int((end_time - start_time).total_seconds())
            
            with db_manager.session() as session:
                # Update run record if exists
                if run_id:
                    task_run = session.query(ScheduledTaskRun).filter(
                        ScheduledTaskRun.id == run_id
                    ).first()
                    if task_run:
                        task_run.completed_at = end_time
                        task_run.status = 'failed'
                        task_run.error_message = str(e)
                        task_run.duration_seconds = duration
                        
                # Update task
                task = session.query(ScheduledTask).filter(
                    ScheduledTask.id == task_id
                ).first()
                if task:
                    task.last_status = 'failed'
                    task.last_error = str(e)
                    task.last_duration_seconds = duration
                    task.total_runs += 1
                    task.failed_runs += 1
                    
                session.commit()
                
    async def _run_task_type_data(self, task_type: str, task_config: dict, task_id: int) -> Dict[str, Any]:
        """Run specific task type with detached data"""
        output = {}
        
        if task_type == 'pipeline':
            # Run main pipeline
            from app.routes.pipeline import run_pipeline_task
            await run_pipeline_task(f"scheduled_{task_id}", "full", None)
            output['type'] = 'full pipeline'
            
        elif task_type == 'misp_import':
            # Import MISP Galaxy
            from app.routes.entities import run_misp_import
            await run_misp_import(f"scheduled_{task_id}", None)
            output['source'] = 'MISP Galaxy'
            
        elif task_type == 'mitre_import':
            # Import MITRE ATT&CK
            from app.routes.entities import run_mitre_import
            await run_mitre_import(f"scheduled_{task_id}", None)
            output['source'] = 'MITRE ATT&CK'
            
        elif task_type == 'ioc_import':
            # Import IOC feeds
            from app.routes.entities import run_ioc_import
            await run_ioc_import(f"scheduled_{task_id}", None)
            output['source'] = 'IOC Feeds'
            
        elif task_type == 'ioc_cleanup':
            # Cleanup old IOCs
            from app.routes.entities import run_ioc_cleanup
            await run_ioc_cleanup(f"scheduled_{task_id}", None)
            retention_days = task_config.get('retention_days', 90)
            output['retention_days'] = retention_days
            
        else:
            raise ValueError(f"Unknown task type: {task_type}")
            
        return output
        
    async def add_task(self, task: ScheduledTask):
        """Add a new scheduled task"""
        self._schedule_task(task)
        
    async def update_task(self, task_id: int):
        """Update an existing task"""
        # Remove old job if exists
        if task_id in self.active_tasks:
            self.scheduler.remove_job(f"task_{task_id}")
            del self.active_tasks[task_id]
            
        # Reload task from database
        with db_manager.session() as session:
            task = session.query(ScheduledTask).filter(
                ScheduledTask.id == task_id
            ).first()
            if task and task.enabled:
                self._schedule_task(task)
                
    async def remove_task(self, task_id: int):
        """Remove a scheduled task"""
        if task_id in self.active_tasks:
            self.scheduler.remove_job(f"task_{task_id}")
            del self.active_tasks[task_id]
            
    def get_task_status(self, task_id: int) -> Optional[Dict]:
        """Get current task status"""
        job = self.active_tasks.get(task_id)
        if job:
            return {
                'id': task_id,
                'name': job.name,
                'next_run': job.next_run_time,
                'active': True
            }
        return None


# Global scheduler instance
scheduler = TaskScheduler()
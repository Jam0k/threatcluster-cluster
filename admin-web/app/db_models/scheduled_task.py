"""
Scheduled Task Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class ScheduledTask(Base):
    """Model for scheduled tasks"""
    __tablename__ = 'scheduled_tasks'
    __table_args__ = {'schema': 'cluster'}
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    task_type = Column(String(100), nullable=False)  # pipeline, misp_import, mitre_import, ioc_import, ioc_cleanup
    description = Column(Text)
    
    # Schedule configuration
    enabled = Column(Boolean, default=True)
    schedule_type = Column(String(50), nullable=False)  # cron, interval, daily, weekly, monthly
    schedule_config = Column(JSON, nullable=False)  # Cron expression or interval config
    
    # Execution tracking
    last_run = Column(DateTime(timezone=True))
    next_run = Column(DateTime(timezone=True))
    last_status = Column(String(50))  # success, failed, running
    last_error = Column(Text)
    last_duration_seconds = Column(Integer)
    
    # Statistics
    total_runs = Column(Integer, default=0)
    successful_runs = Column(Integer, default=0)
    failed_runs = Column(Integer, default=0)
    
    # Task-specific configuration
    task_config = Column(JSON, default={})  # Pipeline stages, IOC retention days, etc.
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class ScheduledTaskRun(Base):
    """Model for task execution history"""
    __tablename__ = 'scheduled_task_runs'
    __table_args__ = {'schema': 'cluster'}
    
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, nullable=False)
    
    # Execution details
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True))
    status = Column(String(50), nullable=False)  # running, success, failed
    error_message = Column(Text)
    
    # Results
    output = Column(JSON)  # Task-specific output/statistics
    duration_seconds = Column(Integer)
    
    # Resource usage
    memory_mb = Column(Integer)
    cpu_percent = Column(Integer)
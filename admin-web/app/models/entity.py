"""
Entity model for admin web interface
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Entity(Base):
    __tablename__ = 'entities'
    __table_args__ = {'schema': 'cluster_extraction'}
    
    id = Column(Integer, primary_key=True)
    value = Column(String(512), nullable=False, unique=True)
    type = Column(String(100), nullable=False)
    confidence = Column(Float, default=0.8)
    first_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.utcnow)
    occurrence_count = Column(Integer, default=1)
    threat_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
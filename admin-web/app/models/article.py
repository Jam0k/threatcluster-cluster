"""
Article model for admin web interface
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Article(Base):
    __tablename__ = 'articles'
    __table_args__ = {'schema': 'cluster_articles'}
    
    id = Column(Integer, primary_key=True)
    title = Column(String(1024), nullable=False)
    url = Column(String(2048), nullable=False, unique=True)
    content = Column(Text)
    source = Column(String(256))
    published_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

class ArticleEntity(Base):
    __tablename__ = 'article_entities'
    __table_args__ = {'schema': 'cluster_extraction'}
    
    id = Column(Integer, primary_key=True)
    article_id = Column(Integer, ForeignKey('cluster_articles.articles.id'), nullable=False)
    entity_id = Column(Integer, ForeignKey('cluster_extraction.entities.id'), nullable=False)
    confidence = Column(Float, default=0.8)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
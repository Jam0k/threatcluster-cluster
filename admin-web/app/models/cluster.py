"""
Cluster model for admin web interface
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Cluster(Base):
    __tablename__ = 'clusters'
    __table_args__ = {'schema': 'cluster_analysis'}
    
    id = Column(Integer, primary_key=True)
    title = Column(String(512))
    description = Column(Text)
    centroid_article_id = Column(Integer, ForeignKey('cluster_articles.articles.id'))
    article_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

class ClusterArticle(Base):
    __tablename__ = 'cluster_articles'
    __table_args__ = {'schema': 'cluster_analysis'}
    
    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey('cluster_analysis.clusters.id'), nullable=False)
    article_id = Column(Integer, ForeignKey('cluster_articles.articles.id'), nullable=False)
    similarity_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class ClusterSharedEntity(Base):
    __tablename__ = 'cluster_shared_entities'
    __table_args__ = {'schema': 'cluster_analysis'}
    
    id = Column(Integer, primary_key=True)
    cluster_id = Column(Integer, ForeignKey('cluster_analysis.clusters.id'), nullable=False)
    entity_id = Column(Integer, ForeignKey('cluster_extraction.entities.id'), nullable=False)
    shared_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
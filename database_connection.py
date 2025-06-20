#!/usr/bin/env python3
"""
Database connection management for ThreatCluster
"""

import os
from contextlib import contextmanager
from typing import Optional
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool

# Load .env file if it exists (but not in Docker)
# In Docker, environment variables should come from docker-compose.yml
if not os.environ.get('DOCKER_CONTAINER'):
    try:
        from dotenv import load_dotenv
        # Look for .env in current directory (cluster)
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        if os.path.exists(env_path):
            load_dotenv(env_path)
            print(f"Loaded .env from {env_path}")
    except ImportError:
        pass

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions"""
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize database manager
        
        Args:
            connection_string: PostgreSQL connection string
                             If not provided, will use environment variables
        """
        if connection_string is None:
            # First try DATABASE_URL from .env
            connection_string = os.getenv('DATABASE_URL')
            
            if not connection_string:
                # Build from individual environment variables
                db_host = os.getenv('DB_HOST', os.getenv('POSTGRES_HOST', 'localhost'))
                db_port = os.getenv('DB_PORT', os.getenv('POSTGRES_PORT', '5432'))
                db_name = os.getenv('DB_NAME', os.getenv('POSTGRES_DB', 'cluster_data'))
                db_user = os.getenv('DB_USER', os.getenv('POSTGRES_USER', 'postgres'))
                db_password = os.getenv('DB_PASSWORD', os.getenv('POSTGRES_PASSWORD', 'postgres'))
                
                connection_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        
        self.connection_string = connection_string
        
        # Create engine with connection pooling
        self.engine = create_engine(
            self.connection_string,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True,  # Verify connections before using
            echo=False  # Set to True for SQL debugging
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        # Extract database info from connection string for logging
        import re
        match = re.search(r'@([^:/]+):?(\d*)/([^?]+)', self.connection_string)
        if match:
            host, port, dbname = match.groups()
            port = port or '5432'
            logger.info(f"Database connection initialized to {host}:{port}/{dbname}")
        else:
            logger.info("Database connection initialized")
    
    @contextmanager
    def session(self) -> Session:
        """
        Provide a transactional scope for database operations
        
        Usage:
            with db_manager.session() as session:
                # Do database operations
                session.query(...)
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def test_connection(self) -> bool:
        """Test if database connection works"""
        try:
            with self.session() as session:
                result = session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def create_schema(self):
        """Create the cluster schema if it doesn't exist"""
        try:
            with self.session() as session:
                session.execute(text("CREATE SCHEMA IF NOT EXISTS cluster"))
                session.commit()
                logger.info("Schema 'cluster' created or verified")
        except Exception as e:
            logger.error(f"Failed to create schema: {e}")
            raise


# Global database manager instance
# Commented out - each app should create its own with proper config
# db_manager = DatabaseManager()


# Repository base classes (minimal implementation for now)
class BaseRepository:
    """Base repository class"""
    
    def __init__(self, session: Session):
        self.session = session


class FeedRepository(BaseRepository):
    """Repository for feed operations"""
    
    def get_active_feeds(self):
        """Get all active feeds"""
        result = self.session.execute(text("""
            SELECT id, url, name, category 
            FROM cluster.feeds 
            WHERE is_active = TRUE
            ORDER BY name
        """))
        
        # Return as objects with attributes
        class Feed:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
        
        return [Feed(**dict(row._mapping)) for row in result]


class ArticleRepository(BaseRepository):
    """Repository for article operations"""
    
    def create(self, **kwargs):
        """Create a new article"""
        # Build insert query
        columns = []
        values = {}
        
        # Map kwargs to columns
        column_mapping = {
            'url': 'url',
            'title': 'title',
            'content': 'content',
            'source': 'source',
            'feed_id': 'feed_id',
            'published_date': 'published_date',
            'image_url': 'image_url'
        }
        
        for key, column in column_mapping.items():
            if key in kwargs and kwargs[key] is not None:
                columns.append(column)
                values[key] = kwargs[key]
        
        if not columns:
            raise ValueError("No valid article data provided")
        
        # Build query
        column_list = ', '.join(columns)
        value_list = ', '.join([f':{key}' for key in values.keys()])
        
        query = text(f"""
            INSERT INTO cluster.articles ({column_list})
            VALUES ({value_list})
            RETURNING id, url, title, content, source, feed_id, published_date, fetched_at
        """)
        
        try:
            result = self.session.execute(query, values)
            row = result.fetchone()
            
            # Return as object
            class Article:
                def __init__(self, row):
                    self.id = row.id
                    self.url = row.url
                    self.title = row.title
                    self.content = row.content
                    self.source = row.source
                    self.feed_id = row.feed_id
                    self.published_date = row.published_date
                    self.fetched_at = row.fetched_at
            
            return Article(row)
        except Exception as e:
            # If duplicate, return None
            if 'duplicate key' in str(e):
                return None
            raise
    
    def get_by_url(self, url: str):
        """Get article by URL"""
        result = self.session.execute(text("""
            SELECT * FROM cluster.articles WHERE url = :url
        """), {'url': url})
        return result.fetchone()
    
    def mark_as_processed(self, article_id: int):
        """Mark article as processed"""
        self.session.execute(text("""
            UPDATE cluster.articles 
            SET processed_at = NOW() 
            WHERE id = :id
        """), {'id': article_id})
    
    def get_articles_since(self, cutoff):
        """Get articles since a given date"""
        result = self.session.execute(text("""
            SELECT id, title, url, source, content,
                   COALESCE(published_date, fetched_at) as article_date
            FROM cluster.articles
            WHERE COALESCE(published_date, fetched_at) > :cutoff
            AND processed_at IS NOT NULL
            ORDER BY article_date DESC
        """), {'cutoff': cutoff})
        
        articles = []
        for row in result:
            articles.append({
                'id': row.id,
                'title': row.title,
                'url': row.url,
                'source': row.source,
                'content': row.content,
                'date': row.article_date
            })
        return articles


class EntityRepository(BaseRepository):
    """Repository for entity operations"""
    
    def link_entities_to_article(self, article_id: int, entities: dict):
        """Link entities to an article"""
        if not entities or not article_id:
            return
        
        for entity_type, entity_values in entities.items():
            for value in entity_values:
                try:
                    # First check if a predefined entity exists with this normalized value
                    normalized_value = value.lower()
                    
                    existing_result = self.session.execute(text("""
                        SELECT id, value 
                        FROM cluster.entities 
                        WHERE normalized_value = :normalized_value 
                        AND entity_type = :entity_type
                        AND is_predefined = TRUE
                        LIMIT 1
                    """), {
                        'normalized_value': normalized_value,
                        'entity_type': entity_type
                    })
                    
                    existing = existing_result.fetchone()
                    
                    if existing:
                        # Use the predefined entity
                        entity_id = existing.id
                        # Update occurrence count (handle NULL case)
                        self.session.execute(text("""
                            UPDATE cluster.entities 
                            SET occurrence_count = COALESCE(occurrence_count, 0) + 1
                            WHERE id = :id
                        """), {'id': entity_id})
                    else:
                        # Create new entity or update existing non-predefined
                        result = self.session.execute(text("""
                            INSERT INTO cluster.entities (value, entity_type, normalized_value)
                            VALUES (:value, :entity_type, :normalized_value)
                            ON CONFLICT (value, entity_type) DO UPDATE
                            SET occurrence_count = COALESCE(cluster.entities.occurrence_count, 0) + 1
                            RETURNING id
                        """), {
                            'value': value,
                            'entity_type': entity_type,
                            'normalized_value': normalized_value
                        })
                        
                        entity_id = result.scalar()
                    
                    # Link to article
                    self.session.execute(text("""
                        INSERT INTO cluster.article_entities (article_id, entity_id)
                        VALUES (:article_id, :entity_id)
                        ON CONFLICT (article_id, entity_id) DO NOTHING
                    """), {
                        'article_id': article_id,
                        'entity_id': entity_id
                    })
                except Exception as e:
                    logger.warning(f"Failed to link entity {value}: {e}")


class ClusterRepository(BaseRepository):
    """Repository for cluster operations"""
    pass


class ProcessingRunRepository(BaseRepository):
    """Repository for processing run tracking"""
    
    def start_run(self, metadata: dict):
        """Start a new processing run"""
        result = self.session.execute(text("""
            INSERT INTO cluster.processing_runs (metadata)
            VALUES (:metadata)
            RETURNING id, started_at
        """), {'metadata': metadata})
        
        row = result.fetchone()
        class Run:
            def __init__(self, id, started_at):
                self.id = id
                self.started_at = started_at
        
        return Run(row.id, row.started_at)
    
    def complete_run(self, run_id: int, **stats):
        """Mark run as completed with statistics"""
        self.session.execute(text("""
            UPDATE cluster.processing_runs
            SET completed_at = NOW(),
                status = 'completed',
                articles_fetched = :articles_fetched,
                articles_processed = :articles_processed,
                clusters_created = :clusters_created,
                clusters_updated = :clusters_updated
            WHERE id = :run_id
        """), {'run_id': run_id, **stats})
    
    def fail_run(self, run_id: int, errors: list):
        """Mark run as failed"""
        self.session.execute(text("""
            UPDATE cluster.processing_runs
            SET completed_at = NOW(),
                status = 'failed',
                errors = :errors
            WHERE id = :run_id
        """), {'run_id': run_id, 'errors': errors})


class SystemConfigRepository(BaseRepository):
    """Repository for system configuration"""
    pass
"""
Database connection for admin web
"""
import sys
import os

# Add cluster path
cluster_path = os.path.join(os.path.dirname(__file__), '../../../')
if cluster_path not in sys.path:
    sys.path.append(cluster_path)

from cluster.database_connection import DatabaseManager
from app.core.config import settings

# Create database manager with settings from config
# This will use the DATABASE_URL from environment/config
db_manager = DatabaseManager(settings.DATABASE_URL)
if os.environ.get('DEBUG'):
    print(f"Admin-web DatabaseManager created with URL: {settings.DATABASE_URL}")
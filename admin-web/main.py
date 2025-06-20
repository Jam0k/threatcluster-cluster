#!/usr/bin/env python3
"""
ThreatCluster Admin Panel - Startup Script
"""
import sys
import os
from pathlib import Path

# Only add the minimal paths needed
cluster_path = str(Path(__file__).parent.parent)  # /home/james/Desktop/threatcluster/cluster
threatcluster_path = str(Path(__file__).parent.parent.parent)  # /home/james/Desktop/threatcluster

# Add them at the end to avoid conflicts
if cluster_path not in sys.path:
    sys.path.append(cluster_path)
if threatcluster_path not in sys.path:
    sys.path.append(threatcluster_path)

# Import from our local app directory
from app.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="localhost",
        port=8002,
        reload=True,
        log_level="info"
    )
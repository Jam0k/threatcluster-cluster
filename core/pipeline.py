#!/usr/bin/env python3
"""
ThreatCluster Pipeline
Orchestrates the complete workflow from feed collection to database storage
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import os
import sys

from sqlalchemy.orm import Session

from .entity_extractor import EntityExtractor
from .security_filter import SecurityFilter
from .feed_collector import FeedCollector
from .semantic_clusterer import SemanticClusterer
from .entity_refresher import EntityRefresher
from .ranker import CyberSecurityRanker

logger = logging.getLogger(__name__)


class ThreatClusterPipeline:
    """Main pipeline orchestrating all components"""
    
    def __init__(self, session: Session, config_path: str = None):
        self.session = session
        self.config_path = config_path
        
        # Initialize components
        self.entity_extractor = EntityExtractor(session)
        self.security_filter = SecurityFilter(config_path)
        self.feed_collector = FeedCollector(session, config_path)
        self.semantic_clusterer = SemanticClusterer(session)
        self.entity_refresher = EntityRefresher(session, config_path)
        self.ranker = CyberSecurityRanker(session, config_path)
        
        # Connect components
        self.feed_collector.set_components(self.security_filter, self.entity_extractor)
    
    
    def run_full_pipeline(self) -> Dict:
        """Run complete pipeline from feed collection to ranking"""
        logger.info("Starting ThreatCluster pipeline")
        results = {}
        
        # 1. Collect feeds
        feed_results = self.collect_feeds()
        results['feed_collection'] = feed_results
        
        # 2. Cluster articles
        cluster_results = self.cluster_articles()
        results['clustering'] = cluster_results
        
        # 3. Refresh entities
        entity_results = self.refresh_entities()
        results['entity_refresh'] = entity_results
        
        # 4. Update rankings
        ranking_results = self.update_rankings()
        results['ranking'] = ranking_results
        
        logger.info("Pipeline completed successfully")
        return results
    
    def collect_feeds(self) -> Dict:
        """Collect articles from RSS feeds"""
        logger.info("Starting feed collection...")
        
        try:
            # Collect from all feeds
            articles = self.feed_collector.collect_all_feeds()
            
            # Save to database
            if articles:
                saved_articles = self.feed_collector.save_articles(articles)
                logger.info(f"Saved {len(saved_articles)} articles")
            else:
                saved_articles = []
                logger.warning("No articles collected")
            
            return {
                'status': 'success',
                'total_fetched': self.feed_collector.stats['total_fetched'],
                'security_relevant': self.feed_collector.stats['security_relevant'],
                'filtered_out': self.feed_collector.stats['filtered_out'],
                'saved': len(saved_articles),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Feed collection failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def cluster_articles(self, days_back: int = None) -> Dict:
        """Cluster related articles using semantic similarity"""
        logger.info("Starting semantic article clustering...")
        
        try:
            # Use default of 7 days if not specified
            if days_back is None:
                days_back = 7
            
            # Run semantic clustering
            results = self.semantic_clusterer.cluster_articles(days_back)
            
            logger.info(f"Clustering complete: {results['clusters_created']} clusters created, "
                       f"{results['articles_clustered']} articles clustered")
            
            # Also try to assign unclustered articles to existing clusters
            assign_results = self.semantic_clusterer.assign_to_existing_clusters()
            if assign_results['articles_assigned'] > 0:
                logger.info(f"Assigned {assign_results['articles_assigned']} articles to existing clusters")
            
            return {
                'status': 'success',
                'clusters_created': results['clusters_created'],
                'articles_clustered': results['articles_clustered'],
                'articles_assigned': assign_results['articles_assigned'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Clustering failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def refresh_entities(self, days_back: int = None) -> Dict:
        """Refresh entity database"""
        logger.info("Starting entity refresh...")
        
        try:
            results = self.entity_refresher.refresh_entities(days_back)
            
            logger.info(f"Entity refresh complete: {results['discovered']} discovered, "
                       f"{results['promoted']} promoted, {results['cleaned']} cleaned")
            
            return {
                'status': 'success',
                **results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Entity refresh failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def update_rankings(self) -> Dict:
        """Update article and cluster rankings"""
        logger.info("Starting ranking update...")
        
        try:
            results = self.ranker.update_rankings()
            
            logger.info(f"Ranking complete: {results['clusters_ranked']} clusters, "
                       f"{results['articles_ranked']} articles")
            
            return {
                'status': 'success',
                **results
            }
            
        except Exception as e:
            logger.error(f"Ranking update failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def cleanup(self):
        """Clean up resources"""
        # Semantic clusterer doesn't need cleanup
        pass


def create_pipeline(session: Session, config_path: str = None) -> ThreatClusterPipeline:
    """Factory function to create pipeline instance"""
    return ThreatClusterPipeline(session, config_path)
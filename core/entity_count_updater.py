#!/usr/bin/env python3
"""
Entity Count Updater
Updates occurrence counts for entities based on actual article associations
"""

import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def update_entity_occurrence_counts(session: Session, entity_type: str = None) -> dict:
    """
    Update occurrence counts for entities based on actual article associations
    
    Args:
        session: Database session
        entity_type: Optional - specific entity type to update (e.g., 'mitre_technique')
                    If None, updates all entity types
    
    Returns:
        Dictionary with update statistics
    """
    logger.info(f"Updating entity occurrence counts{f' for {entity_type}' if entity_type else ''}")
    
    try:
        # First, ensure no NULL occurrence counts
        if entity_type:
            result = session.execute(text("""
                UPDATE cluster.entities 
                SET occurrence_count = 0 
                WHERE occurrence_count IS NULL
                AND entity_type = :entity_type
            """), {'entity_type': entity_type})
        else:
            result = session.execute(text("""
                UPDATE cluster.entities 
                SET occurrence_count = 0 
                WHERE occurrence_count IS NULL
            """))
        
        nulls_fixed = result.rowcount
        logger.info(f"Fixed {nulls_fixed} NULL occurrence counts")
        
        # Update occurrence counts based on actual associations
        if entity_type:
            result = session.execute(text("""
                UPDATE cluster.entities e
                SET occurrence_count = COALESCE(counts.article_count, 0)
                FROM (
                    SELECT 
                        entity_id, 
                        COUNT(DISTINCT article_id) as article_count
                    FROM cluster.article_entities
                    GROUP BY entity_id
                ) counts
                WHERE e.id = counts.entity_id
                AND e.entity_type = :entity_type
            """), {'entity_type': entity_type})
        else:
            result = session.execute(text("""
                UPDATE cluster.entities e
                SET occurrence_count = COALESCE(counts.article_count, 0)
                FROM (
                    SELECT 
                        entity_id, 
                        COUNT(DISTINCT article_id) as article_count
                    FROM cluster.article_entities
                    GROUP BY entity_id
                ) counts
                WHERE e.id = counts.entity_id
            """))
        
        updated = result.rowcount
        logger.info(f"Updated {updated} entity occurrence counts")
        
        # Set entities with no associations to 0
        if entity_type:
            result = session.execute(text("""
                UPDATE cluster.entities
                SET occurrence_count = 0
                WHERE entity_type = :entity_type
                AND id NOT IN (
                    SELECT DISTINCT entity_id 
                    FROM cluster.article_entities
                )
                AND (occurrence_count IS NULL OR occurrence_count != 0)
            """), {'entity_type': entity_type})
        else:
            result = session.execute(text("""
                UPDATE cluster.entities
                SET occurrence_count = 0
                WHERE id NOT IN (
                    SELECT DISTINCT entity_id 
                    FROM cluster.article_entities
                )
                AND (occurrence_count IS NULL OR occurrence_count != 0)
            """))
        
        zeroed = result.rowcount
        logger.info(f"Set {zeroed} entities with no associations to 0")
        
        # Get statistics
        if entity_type:
            stats = session.execute(text("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN occurrence_count > 0 THEN 1 END) as with_articles,
                    COUNT(CASE WHEN occurrence_count = 0 THEN 1 END) as without_articles,
                    MAX(occurrence_count) as max_count,
                    AVG(occurrence_count) as avg_count
                FROM cluster.entities
                WHERE entity_type = :entity_type
            """), {'entity_type': entity_type}).fetchone()
        else:
            stats = session.execute(text("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN occurrence_count > 0 THEN 1 END) as with_articles,
                    COUNT(CASE WHEN occurrence_count = 0 THEN 1 END) as without_articles,
                    MAX(occurrence_count) as max_count,
                    AVG(occurrence_count) as avg_count
                FROM cluster.entities
            """)).fetchone()
        
        session.commit()
        
        return {
            'status': 'success',
            'nulls_fixed': nulls_fixed,
            'updated': updated,
            'zeroed': zeroed,
            'statistics': {
                'total_entities': stats.total,
                'with_articles': stats.with_articles,
                'without_articles': stats.without_articles,
                'max_occurrence_count': stats.max_count,
                'avg_occurrence_count': float(stats.avg_count) if stats.avg_count else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Error updating occurrence counts: {e}")
        session.rollback()
        return {
            'status': 'error',
            'error': str(e)
        }


def get_entity_occurrence_stats(session: Session, entity_type: str = None) -> dict:
    """
    Get statistics about entity occurrence counts
    
    Args:
        session: Database session
        entity_type: Optional - specific entity type to check
    
    Returns:
        Dictionary with occurrence statistics
    """
    try:
        if entity_type:
            # Get top entities by occurrence
            top_entities = session.execute(text("""
                SELECT value, occurrence_count
                FROM cluster.entities
                WHERE entity_type = :entity_type
                AND occurrence_count > 0
                ORDER BY occurrence_count DESC
                LIMIT 10
            """), {'entity_type': entity_type}).fetchall()
            
            # Get entities with associations but 0 count (data integrity issue)
            integrity_issues = session.execute(text("""
                SELECT e.value, COUNT(DISTINCT ae.article_id) as actual_count
                FROM cluster.entities e
                JOIN cluster.article_entities ae ON e.id = ae.entity_id
                WHERE e.entity_type = :entity_type
                AND e.occurrence_count = 0
                GROUP BY e.value
                LIMIT 10
            """), {'entity_type': entity_type}).fetchall()
            
        else:
            # Get top entities across all types
            top_entities = session.execute(text("""
                SELECT entity_type, value, occurrence_count
                FROM cluster.entities
                WHERE occurrence_count > 0
                ORDER BY occurrence_count DESC
                LIMIT 20
            """)).fetchall()
            
            # Get integrity issues across all types
            integrity_issues = session.execute(text("""
                SELECT e.entity_type, e.value, COUNT(DISTINCT ae.article_id) as actual_count
                FROM cluster.entities e
                JOIN cluster.article_entities ae ON e.id = ae.entity_id
                WHERE e.occurrence_count = 0
                GROUP BY e.entity_type, e.value
                LIMIT 20
            """)).fetchall()
        
        return {
            'top_entities': [
                {
                    'value': entity.value,
                    'occurrence_count': entity.occurrence_count,
                    'entity_type': getattr(entity, 'entity_type', entity_type)
                }
                for entity in top_entities
            ],
            'integrity_issues': [
                {
                    'value': issue.value,
                    'stored_count': 0,
                    'actual_count': issue.actual_count,
                    'entity_type': getattr(issue, 'entity_type', entity_type)
                }
                for issue in integrity_issues
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting occurrence stats: {e}")
        return {
            'error': str(e),
            'top_entities': [],
            'integrity_issues': []
        }
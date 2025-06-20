#!/usr/bin/env python3
"""
Entity Refresh Module
Discovers new entities and promotes frequently seen ones
"""

import re
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Dict, List, Set
import logging
import yaml
import os

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class EntityRefresher:
    """Manages dynamic entity discovery and database updates"""
    
    def __init__(self, session: Session, config_path: str = None):
        self.session = session
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Promotion thresholds
        self.promotion_thresholds = self.config['entities']['promotion_thresholds']
        
        # Discovery patterns - DISABLED for dynamic extraction
        # These entities should be populated via predefined lists instead
        self.discovery_patterns = {}
        
        # Keeping the old patterns commented for reference
        # self.discovery_patterns = {
        #     'ransomware_group': [...],
        #     'apt_group': [...],
        #     'malware_family': [...]
        # }
        
        # Exclusions
        self.exclusions = {
            'ransomware_group': {
                'The', 'This', 'New', 'Latest', 'Recent', 'Unknown', 'With', 'And',
                'For', 'But', 'Not', 'All', 'Some', 'Many', 'Few', 'Several',
                'First', 'Second', 'Third', 'Next', 'Last', 'Other', 'Another',
                'Confirms', 'Deploy', 'Requires', 'Uses', 'Targets', 'Hits',
                'CPU', 'GPU', 'RAM', 'SSD', 'HDD', 'USB', 'More'
            },
            'apt_group': {
                'The', 'This', 'New', 'Latest', 'Recent', 'Unknown', 'Chinese',
                'Russian', 'Iranian', 'Korean', 'Advanced', 'Persistent', 'Threat'
            },
            'malware_family': {
                'The', 'This', 'New', 'Latest', 'Recent', 'Unknown', 'Windows', 'Linux',
                'Android', 'iOS', 'Mac', 'Both', 'All', 'Some', 'Many', 'These', 'Those',
                'NET', 'COM', 'EXE', 'DLL', 'PDF', 'DOC', 'ZIP', 'RAR',
                'WhatsApp', 'Facebook', 'Twitter', 'LinkedIn', 'Instagram',
                'Stealing', 'Steals', 'Targets', 'Uses', 'Deploys', 'Runs'
            }
        }
    
    def refresh_entities(self, days_back: int = None) -> Dict:
        """Run the entity refresh process"""
        if days_back is None:
            days_back = self.config.get('entities', {}).get('refresh_days', 30)
        
        logger.info(f"Starting entity refresh for last {days_back} days")
        
        # Clean up bad entities
        cleaned = self._cleanup_bad_entities()
        
        # Discover new entities
        discovered = self._discover_new_entities(days_back)
        
        # Update occurrence counts
        self._update_occurrence_counts()
        
        # Promote frequently seen entities
        promoted = self._promote_entities()
        
        # Return statistics
        return {
            'cleaned': cleaned,
            'discovered': discovered,
            'promoted': promoted
        }
    
    def _cleanup_bad_entities(self) -> int:
        """Remove obviously incorrect entities"""
        logger.info("Cleaning up bad entities...")
        
        bad_patterns = [
            '%\n%',  # Contains newlines
            '% is %', '% are %', '% was %', '% were %',  # Contains verbs
            '% will %', '% would %', '% could %',  # Modal verbs
            '%exploit%', '%vector%', '%attack%',  # Technical terms
            '%between%', '%through%', '%across%',  # Prepositions
            '%rapidly%', '%slowly%', '%quickly%',  # Adverbs
        ]
        
        total_removed = 0
        
        for pattern in bad_patterns:
            # Remove from article_entities
            result = self.session.execute(text("""
                DELETE FROM cluster.article_entities
                WHERE entity_id IN (
                    SELECT id FROM cluster.entities
                    WHERE entity_type = 'other'
                    AND value ILIKE :pattern
                )
            """), {'pattern': pattern})
            
            # Remove from entities
            result = self.session.execute(text("""
                DELETE FROM cluster.entities
                WHERE entity_type = 'other'
                AND value ILIKE :pattern
                AND NOT is_predefined
            """), {'pattern': pattern})
            
            total_removed += result.rowcount
        
        self.session.commit()
        logger.info(f"Removed {total_removed} bad entities")
        return total_removed
    
    def _discover_new_entities(self, days_back: int) -> Dict[str, int]:
        """Discover potential new entities from recent articles"""
        logger.info("Entity discovery disabled - entities should be populated via predefined lists")
        
        # Dynamic discovery is disabled to avoid false positives
        # apt_group, malware_family, ransomware_group, and campaign entities
        # should be populated via predefined lists instead
        
        return {}
    
    def _update_occurrence_counts(self):
        """Update occurrence counts for all entities"""
        logger.info("Updating entity occurrence counts...")
        
        self.session.execute(text("""
            UPDATE cluster.entities e
            SET occurrence_count = subquery.count
            FROM (
                SELECT entity_id, COUNT(DISTINCT article_id) as count
                FROM cluster.article_entities
                GROUP BY entity_id
            ) AS subquery
            WHERE e.id = subquery.entity_id
        """))
        
        self.session.commit()
        logger.info("Updated occurrence counts")
    
    def _promote_entities(self) -> Dict[str, List[str]]:
        """Promote frequently seen entities to predefined status"""
        logger.info("Promoting frequently seen entities...")
        
        promoted = defaultdict(list)
        
        for entity_type, threshold in self.promotion_thresholds.items():
            candidates = self.session.execute(text("""
                SELECT id, value, occurrence_count
                FROM cluster.entities
                WHERE entity_type = :entity_type
                AND is_predefined = FALSE
                AND occurrence_count >= :threshold
            """), {
                'entity_type': entity_type,
                'threshold': threshold
            }).fetchall()
            
            for candidate in candidates:
                # Additional validation for 'other' entities
                if entity_type == 'other':
                    if (len(candidate.value) > 40 or
                        ' is ' in candidate.value.lower() or
                        ' are ' in candidate.value.lower() or
                        '\n' in candidate.value):
                        continue
                
                # Promote
                self.session.execute(text("""
                    UPDATE cluster.entities
                    SET is_predefined = TRUE
                    WHERE id = :id
                """), {'id': candidate.id})
                
                promoted[entity_type].append(candidate.value)
                logger.info(f"Promoted {entity_type}: {candidate.value} (seen {candidate.occurrence_count} times)")
        
        self.session.commit()
        
        total_promoted = sum(len(entities) for entities in promoted.values())
        logger.info(f"Promoted {total_promoted} entities to predefined status")
        
        return dict(promoted)
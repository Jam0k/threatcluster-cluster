#!/usr/bin/env python3
"""
MITRE ATT&CK Importer
Imports MITRE ATT&CK techniques into the entities table
"""

import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class MITREAttackImporter:
    """Import MITRE ATT&CK techniques from official sources"""
    
    # MITRE ATT&CK STIX data URL
    ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    def __init__(self, session: Session):
        self.session = session
        self.stats = {
            'total_processed': 0,
            'new_entities': 0,
            'updated_entities': 0,
            'errors': 0,
            'skipped': 0
        }
        self.technique_map = {}  # Map of technique IDs to names for deduplication
    
    async def import_techniques(self) -> Dict[str, Any]:
        """Import all MITRE ATT&CK techniques"""
        logger.info("Starting MITRE ATT&CK technique import")
        
        try:
            # Download the STIX data
            techniques = await self._fetch_attack_data()
            
            if not techniques:
                return {
                    'status': 'error',
                    'message': 'No techniques found in MITRE ATT&CK data',
                    'stats': self.stats
                }
            
            # Import each technique
            for technique in techniques:
                try:
                    result = self._import_technique(technique)
                    
                    if result == 'new':
                        self.stats['new_entities'] += 1
                    elif result == 'updated':
                        self.stats['updated_entities'] += 1
                    elif result == 'skipped':
                        self.stats['skipped'] += 1
                        
                    self.stats['total_processed'] += 1
                    
                except Exception as e:
                    logger.error(f"Error importing technique '{technique.get('id', 'unknown')}': {e}")
                    self.stats['errors'] += 1
            
            # Commit the transaction
            self.session.commit()
            
            return {
                'status': 'success',
                'message': f"Successfully imported {self.stats['new_entities']} new techniques, updated {self.stats['updated_entities']}",
                'stats': self.stats,
                'technique_map': self.technique_map
            }
            
        except Exception as e:
            logger.error(f"Failed to import MITRE ATT&CK techniques: {e}")
            self.session.rollback()
            return {
                'status': 'error',
                'message': str(e),
                'stats': self.stats
            }
    
    async def _fetch_attack_data(self) -> List[Dict[str, Any]]:
        """Fetch MITRE ATT&CK data from GitHub"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.ATTACK_STIX_URL) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status} when fetching MITRE ATT&CK data")
                    
                    # Read as text first
                    text = await response.text()
                    data = json.loads(text)
            
            # Extract techniques from STIX bundle
            techniques = []
            for obj in data.get('objects', []):
                # Look for attack-pattern objects (techniques)
                if obj.get('type') == 'attack-pattern':
                    # Extract technique ID from external references
                    technique_id = None
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            technique_id = ref.get('external_id')
                            break
                    
                    if technique_id and technique_id.startswith('T'):
                        techniques.append({
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'kill_chain_phases': obj.get('kill_chain_phases', []),
                            'x_mitre_platforms': obj.get('x_mitre_platforms', []),
                            'x_mitre_tactics': self._extract_tactics(obj),
                            'x_mitre_data_sources': obj.get('x_mitre_data_sources', []),
                            'x_mitre_is_subtechnique': obj.get('x_mitre_is_subtechnique', False),
                            'created': obj.get('created'),
                            'modified': obj.get('modified')
                        })
            
            logger.info(f"Found {len(techniques)} techniques in MITRE ATT&CK data")
            return techniques
            
        except Exception as e:
            logger.error(f"Error fetching MITRE ATT&CK data: {e}")
            raise
    
    def _extract_tactics(self, obj: Dict[str, Any]) -> List[str]:
        """Extract tactic names from kill chain phases"""
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic = phase.get('phase_name', '').replace('-', ' ').title()
                tactics.append(tactic)
        return tactics
    
    def _import_technique(self, technique: Dict[str, Any]) -> str:
        """Import a single technique into the database"""
        technique_id = technique['id']
        technique_name = technique['name']
        
        # Build metadata
        metadata = {
            'mitre_id': technique_id,
            'description': technique['description'],
            'tactics': technique['x_mitre_tactics'],
            'platforms': technique['x_mitre_platforms'],
            'data_sources': technique['x_mitre_data_sources'],
            'is_subtechnique': technique['x_mitre_is_subtechnique'],
            'created': technique['created'],
            'modified': technique['modified']
        }
        
        # Clean metadata (remove None values)
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        # Store in technique map for deduplication
        self.technique_map[technique_id] = technique_name
        
        # Check if technique already exists
        existing = self.session.execute(
            text("""
                SELECT id, value, metadata 
                FROM cluster.entities 
                WHERE value = :value AND entity_type = 'mitre_technique'
            """),
            {'value': technique_id}
        ).fetchone()
        
        if existing:
            # Update existing technique
            self.session.execute(
                text("""
                    UPDATE cluster.entities 
                    SET metadata = :metadata,
                        normalized_value = :normalized_value,
                        updated_at = NOW()
                    WHERE id = :id
                """),
                {
                    'id': existing.id,
                    'metadata': json.dumps(metadata),
                    'normalized_value': f"{technique_id} - {technique_name}".lower()
                }
            )
            return 'updated'
        else:
            # Insert new technique
            self.session.execute(
                text("""
                    INSERT INTO cluster.entities 
                    (value, entity_type, is_predefined, normalized_value, metadata, confidence_score)
                    VALUES (:value, :entity_type, :is_predefined, :normalized_value, :metadata, :confidence)
                """),
                {
                    'value': technique_id,
                    'entity_type': 'mitre_technique',
                    'is_predefined': True,
                    'normalized_value': f"{technique_id} - {technique_name}".lower(),
                    'metadata': json.dumps(metadata),
                    'confidence': 1.0
                }
            )
            
            # Also insert the technique name as an alias
            self._insert_technique_name_alias(technique_id, technique_name, metadata)
            
            return 'new'
    
    def _insert_technique_name_alias(self, technique_id: str, technique_name: str, full_metadata: Dict[str, Any]):
        """Insert technique name as an additional entity for name-based matching"""
        # Check if name already exists
        existing = self.session.execute(
            text("""
                SELECT id FROM cluster.entities 
                WHERE value = :value AND entity_type = 'mitre_technique'
            """),
            {'value': technique_name}
        ).fetchone()
        
        if not existing:
            # Insert technique name as an entity linked to the ID with full metadata
            alias_metadata = full_metadata.copy()
            alias_metadata['mitre_id'] = technique_id
            alias_metadata['is_name_alias'] = True
            
            self.session.execute(
                text("""
                    INSERT INTO cluster.entities 
                    (value, entity_type, is_predefined, normalized_value, metadata, confidence_score)
                    VALUES (:value, :entity_type, :is_predefined, :normalized_value, :metadata, :confidence)
                """),
                {
                    'value': technique_name,
                    'entity_type': 'mitre_technique',
                    'is_predefined': True,
                    'normalized_value': technique_name.lower(),
                    'metadata': json.dumps(alias_metadata),
                    'confidence': 1.0
                }
            )
    
    def get_technique_stats(self) -> Dict[str, Any]:
        """Get statistics about imported techniques"""
        result = self.session.execute(
            text("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN metadata->>'is_subtechnique' = 'true' THEN 1 END) as subtechniques,
                    COUNT(CASE WHEN metadata->>'is_name_alias' = 'true' THEN 1 END) as name_aliases
                FROM cluster.entities
                WHERE entity_type = 'mitre_technique'
            """)
        ).fetchone()
        
        # Update occurrence counts after import
        from .entity_count_updater import update_entity_occurrence_counts
        logger.info("Updating occurrence counts for MITRE techniques...")
        count_results = update_entity_occurrence_counts(self.session, 'mitre_technique')
        
        return {
            'total_techniques': result.total if result else 0,
            'subtechniques': result.subtechniques if result else 0,
            'name_aliases': result.name_aliases if result else 0,
            'unique_techniques': len(self.technique_map),
            'occurrence_count_update': count_results
        }
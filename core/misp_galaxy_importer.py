#!/usr/bin/env python3
"""
MISP Galaxy Importer
Imports threat actor data from MISP Galaxy JSON files into the entities table
"""

import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from sqlalchemy import text
from sqlalchemy.orm import Session
from pathlib import Path
from .ransomlook import RansomLookClient

logger = logging.getLogger(__name__)


class MISPGalaxyImporter:
    """Import threat actor data from MISP Galaxy repositories"""
    
    # MISP Galaxy URLs
    GALAXY_URLS = {
        'ransomware_group': 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json',
        'apt_group': 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json',
        'malware_family': 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json'
    }
    
    def __init__(self, session: Session):
        self.session = session
        self.stats = {
            'total_processed': 0,
            'new_entities': 0,
            'updated_entities': 0,
            'errors': 0
        }
    
    def _clean_metadata(self, data: Any) -> Any:
        """Recursively remove 'screen' and 'source' fields from metadata"""
        if isinstance(data, dict):
            # Create a new dict without screen and source keys
            cleaned = {}
            for key, value in data.items():
                if key not in ('screen', 'source'):
                    cleaned[key] = self._clean_metadata(value)
            return cleaned
        elif isinstance(data, list):
            # Recursively clean items in lists
            return [self._clean_metadata(item) for item in data]
        else:
            # Return other types as-is
            return data
    
    async def import_all(self) -> Dict[str, Any]:
        """Import all configured MISP Galaxy feeds"""
        logger.info("Starting MISP Galaxy import for all threat actor types")
        
        results = {}
        for entity_type, url in self.GALAXY_URLS.items():
            logger.info(f"Importing {entity_type} from MISP Galaxy")
            result = await self.import_galaxy(entity_type, url)
            results[entity_type] = result
        
        return {
            'results': results,
            'total_stats': self.stats
        }
    
    async def import_specific(self, entity_types: List[str]) -> Dict[str, Any]:
        """Import specific entity types from MISP Galaxy"""
        results = {}
        
        for entity_type in entity_types:
            if entity_type not in self.GALAXY_URLS:
                logger.error(f"Unknown entity type: {entity_type}")
                results[entity_type] = {'status': 'error', 'message': 'Unknown entity type'}
                continue
                
            url = self.GALAXY_URLS[entity_type]
            logger.info(f"Importing {entity_type} from MISP Galaxy")
            result = await self.import_galaxy(entity_type, url)
            results[entity_type] = result
        
        return {
            'results': results,
            'total_stats': self.stats
        }
    
    async def import_galaxy(self, entity_type: str, url: str) -> Dict[str, Any]:
        """Import a single MISP Galaxy JSON file"""
        try:
            # Special handling for ransomware groups - use RansomLook API
            if entity_type == 'ransomware_group':
                return await self._import_ransomware_from_ransomlook()
            
            # Download the JSON data
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status} when fetching {url}")
                    
                    # Read as text first since GitHub serves raw files as text/plain
                    text = await response.text()
                    data = json.loads(text)
            
            # Process the values
            values = data.get('values', [])
            if not values:
                return {
                    'status': 'warning',
                    'message': 'No values found in Galaxy data',
                    'count': 0
                }
            
            # Import each value
            imported = 0
            updated = 0
            errors = 0
            
            for item in values:
                try:
                    if entity_type == 'ransomware_group':
                        result = self._import_ransomware(item)
                    elif entity_type == 'apt_group':
                        result = self._import_apt_group(item)
                    elif entity_type == 'malware_family':
                        result = self._import_malware(item)
                    else:
                        logger.warning(f"Unsupported entity type: {entity_type}")
                        continue
                    
                    if result == 'new':
                        imported += 1
                        self.stats['new_entities'] += 1
                    elif result == 'updated':
                        updated += 1
                        self.stats['updated_entities'] += 1
                        
                    self.stats['total_processed'] += 1
                    
                except Exception as e:
                    logger.error(f"Error importing {entity_type} '{item.get('value', 'unknown')}': {e}")
                    errors += 1
                    self.stats['errors'] += 1
            
            # Commit the transaction
            self.session.commit()
            
            return {
                'status': 'success',
                'imported': imported,
                'updated': updated,
                'errors': errors,
                'total': len(values)
            }
            
        except Exception as e:
            logger.error(f"Failed to import {entity_type} from {url}: {e}")
            self.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _import_ransomware(self, item: Dict[str, Any]) -> str:
        """Import a ransomware entry"""
        value = item.get('value', '').strip()
        if not value:
            return 'skip'
        
        # Clean up the value - remove suffixes like " Ransomware" or " (Fake)"
        cleaned_value = value
        for suffix in [' Ransomware', ' (Fake)', ' ransomware']:
            if cleaned_value.endswith(suffix):
                cleaned_value = cleaned_value[:-len(suffix)].strip()
        
        # Prepare metadata
        metadata = {
            'uuid': item.get('uuid'),
            'description': item.get('description'),
            'meta': self._clean_metadata(item.get('meta', {})),
            'original_value': value,
            'import_date': datetime.now(timezone.utc).isoformat()
        }
        
        # Check if entity exists
        existing = self.session.execute(text("""
            SELECT id, metadata 
            FROM cluster.entities 
            WHERE value = :value AND entity_type = 'ransomware_group'
        """), {'value': cleaned_value}).fetchone()
        
        if existing:
            # Update metadata
            self.session.execute(text("""
                UPDATE cluster.entities 
                SET metadata = :metadata,
                    updated_at = NOW()
                WHERE id = :id
            """), {
                'id': existing.id,
                'metadata': json.dumps(metadata)
            })
            return 'updated'
        else:
            # Insert new entity
            self.session.execute(text("""
                INSERT INTO cluster.entities 
                (value, entity_type, is_predefined, occurrence_count, normalized_value, metadata)
                VALUES (:value, 'ransomware_group', TRUE, 0, :normalized_value, :metadata)
            """), {
                'value': cleaned_value,
                'normalized_value': cleaned_value.lower(),
                'metadata': json.dumps(metadata)
            })
            return 'new'
    
    def _import_apt_group(self, item: Dict[str, Any]) -> str:
        """Import an APT group entry"""
        value = item.get('value', '').strip()
        if not value:
            return 'skip'
        
        # Prepare metadata
        metadata = {
            'uuid': item.get('uuid'),
            'description': item.get('description'),
            'meta': self._clean_metadata(item.get('meta', {})),
            'import_date': datetime.now(timezone.utc).isoformat()
        }
        
        # Check if entity exists
        existing = self.session.execute(text("""
            SELECT id, metadata 
            FROM cluster.entities 
            WHERE value = :value AND entity_type = 'apt_group'
        """), {'value': value}).fetchone()
        
        if existing:
            # Update metadata
            self.session.execute(text("""
                UPDATE cluster.entities 
                SET metadata = :metadata,
                    updated_at = NOW()
                WHERE id = :id
            """), {
                'id': existing.id,
                'metadata': json.dumps(metadata)
            })
            return 'updated'
        else:
            # Insert new entity
            self.session.execute(text("""
                INSERT INTO cluster.entities 
                (value, entity_type, is_predefined, occurrence_count, normalized_value, metadata)
                VALUES (:value, 'apt_group', TRUE, 0, :normalized_value, :metadata)
            """), {
                'value': value,
                'normalized_value': value.lower(),
                'metadata': json.dumps(metadata)
            })
            return 'new'
    
    def _import_malware(self, item: Dict[str, Any]) -> str:
        """Import a malware family entry"""
        value = item.get('value', '').strip()
        if not value:
            return 'skip'
        
        # For Malpedia format, the value might be like "win.agent_tesla"
        # Extract just the malware name
        if '.' in value:
            platform, malware_name = value.split('.', 1)
            # Convert underscore to space and capitalize
            cleaned_value = malware_name.replace('_', ' ').title()
            # Store platform in metadata
            platform_info = {'platform': platform}
        else:
            cleaned_value = value
            platform_info = {}
        
        # Prepare metadata
        metadata = {
            'uuid': item.get('uuid'),
            'description': item.get('description'),
            'meta': self._clean_metadata(item.get('meta', {})),
            'original_value': value,
            'import_date': datetime.now(timezone.utc).isoformat(),
            **platform_info
        }
        
        # Check if entity exists
        existing = self.session.execute(text("""
            SELECT id, metadata 
            FROM cluster.entities 
            WHERE value = :value AND entity_type = 'malware_family'
        """), {'value': cleaned_value}).fetchone()
        
        if existing:
            # Update metadata
            self.session.execute(text("""
                UPDATE cluster.entities 
                SET metadata = :metadata,
                    updated_at = NOW()
                WHERE id = :id
            """), {
                'id': existing.id,
                'metadata': json.dumps(metadata)
            })
            return 'updated'
        else:
            # Insert new entity
            self.session.execute(text("""
                INSERT INTO cluster.entities 
                (value, entity_type, is_predefined, occurrence_count, normalized_value, metadata)
                VALUES (:value, 'malware_family', TRUE, 0, :normalized_value, :metadata)
            """), {
                'value': cleaned_value,
                'normalized_value': cleaned_value.lower(),
                'metadata': json.dumps(metadata)
            })
            return 'new'
    
    async def _import_ransomware_from_ransomlook(self) -> Dict[str, Any]:
        """Import ransomware groups from RansomLook API"""
        imported = 0
        updated = 0
        errors = 0
        
        try:
            async with RansomLookClient() as client:
                # Get all groups with details
                groups_with_details = await client.get_all_groups_with_details()
                
                for group_data in groups_with_details:
                    try:
                        group_name = group_data['name']
                        details = group_data['details']
                        
                        # Prepare metadata
                        metadata = {
                            'import_date': datetime.now(timezone.utc).isoformat()
                        }
                        
                        # Add details if available, ensuring they're cleaned
                        if details:
                            metadata['ransomlook_details'] = self._clean_metadata(details)
                        
                        # Check if entity exists
                        existing = self.session.execute(text("""
                            SELECT id, metadata 
                            FROM cluster.entities 
                            WHERE value = :value AND entity_type = 'ransomware_group'
                        """), {'value': group_name}).fetchone()
                        
                        if existing:
                            # Update metadata
                            self.session.execute(text("""
                                UPDATE cluster.entities 
                                SET metadata = :metadata,
                                    updated_at = NOW()
                                WHERE id = :id
                            """), {
                                'id': existing.id,
                                'metadata': json.dumps(metadata)
                            })
                            updated += 1
                            self.stats['updated_entities'] += 1
                        else:
                            # Insert new entity
                            self.session.execute(text("""
                                INSERT INTO cluster.entities 
                                (value, entity_type, is_predefined, occurrence_count, normalized_value, metadata)
                                VALUES (:value, 'ransomware_group', TRUE, 0, :normalized_value, :metadata)
                            """), {
                                'value': group_name,
                                'normalized_value': group_name.lower(),
                                'metadata': json.dumps(metadata)
                            })
                            imported += 1
                            self.stats['new_entities'] += 1
                        
                        self.stats['total_processed'] += 1
                        
                    except Exception as e:
                        logger.error(f"Error importing ransomware group '{group_data.get('name', 'unknown')}': {e}")
                        errors += 1
                        self.stats['errors'] += 1
                
                # Commit the transaction
                self.session.commit()
                
                return {
                    'status': 'success',
                    'imported': imported,
                    'updated': updated,
                    'errors': errors,
                    'total': len(groups_with_details)
                }
                
        except Exception as e:
            logger.error(f"Failed to import ransomware groups from RansomLook: {e}")
            self.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def get_import_stats(self) -> Dict[str, Any]:
        """Get import statistics"""
        return self.stats.copy()
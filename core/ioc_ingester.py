#!/usr/bin/env python3
"""
IOC Ingestion Service
Pulls indicators of compromise (IPs, hashes, domains) from GitHub threat intelligence lists
"""

import re
import logging
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Tuple
from sqlalchemy import text
from sqlalchemy.orm import Session
import yaml
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class IOCIngester:
    """Ingests IOCs from various GitHub-hosted threat intelligence feeds"""
    
    def __init__(self, session: Session, config_path: Optional[str] = None):
        self.session = session
        
        # Load configuration
        if config_path is None:
            config_path = Path(__file__).parent / 'ioc_feeds.yaml'
        
        self.config = self._load_config(config_path)
        self.feeds = self.config.get('feeds', [])
        
        # Regex patterns for IOC extraction
        self.patterns = {
            'ip_address': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
            'domain': re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
            'file_hash': {
                'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
                'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
                'sha256': re.compile(r'^[a-fA-F0-9]{64}$')
            }
        }
        
        # Statistics
        self.stats = {
            'feeds_processed': 0,
            'iocs_found': 0,
            'iocs_added': 0,
            'iocs_updated': 0,
            'errors': 0
        }
    
    def _load_config(self, config_path: Path) -> Dict:
        """Load feed configuration"""
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                logger.error(f"Configuration file not found: {config_path}")
                return {'feeds': [], 'settings': {}}
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {'feeds': [], 'settings': {}}
    
    async def ingest_all_feeds(self) -> Dict:
        """Process all configured feeds"""
        logger.info("Starting IOC ingestion from configured feeds")
        
        # Reset statistics
        self.stats = {
            'feeds_processed': 0,
            'iocs_found': 0,
            'iocs_added': 0,
            'iocs_updated': 0,
            'errors': 0
        }
        
        # Process feeds concurrently
        async with aiohttp.ClientSession(
            headers={'User-Agent': self.config['settings']['user_agent']},
            timeout=aiohttp.ClientTimeout(total=self.config['settings']['timeout'])
        ) as session:
            tasks = []
            for feed in self.feeds:
                if feed.get('active', True):
                    tasks.append(self._process_feed(session, feed))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Log any exceptions
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Feed '{self.feeds[i]['name']}' failed: {result}")
                        self.stats['errors'] += 1
        
        logger.info(f"IOC ingestion complete: {self.stats}")
        return self.stats
    
    async def _process_feed(self, session: aiohttp.ClientSession, feed: Dict):
        """Process a single feed"""
        logger.info(f"Processing feed: {feed['name']}")
        
        try:
            # Download feed content
            content = await self._download_feed(session, feed['url'])
            if not content:
                return
            
            # Extract IOCs based on feed configuration
            iocs = self._extract_iocs(content, feed)
            logger.info(f"Extracted {len(iocs)} IOCs from {feed['name']}")
            
            # Store IOCs in database
            stored = self._store_iocs(iocs, feed['name'])
            
            self.stats['feeds_processed'] += 1
            self.stats['iocs_found'] += len(iocs)
            
        except Exception as e:
            logger.error(f"Error processing feed '{feed['name']}': {e}")
            self.stats['errors'] += 1
    
    async def _download_feed(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Download feed content"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.error(f"HTTP {response.status} when fetching {url}")
                    return None
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return None
    
    def _extract_iocs(self, content: str, feed: Dict) -> List[Tuple[str, str]]:
        """Extract IOCs from feed content"""
        iocs = []
        lines = content.strip().split('\n')
        
        # Skip header lines if configured
        skip_lines = feed.get('skip_lines', 0)
        lines = lines[skip_lines:]
        
        feed_type = feed.get('type', 'mixed')
        feed_format = feed.get('format', 'plain')
        
        if feed_format == 'plain':
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                # Clean common formatting
                line = line.split('#')[0].strip()  # Remove inline comments
                line = line.split(',')[0].strip()  # Take first column if CSV-like
                line = line.split('\t')[0].strip()  # Take first column if TSV-like
                
                if feed_type == 'mixed':
                    # Try to detect IOC type
                    ioc_type = self._detect_ioc_type(line)
                    if ioc_type:
                        iocs.append((line.lower(), ioc_type))
                else:
                    # Validate against expected type
                    if self._validate_ioc(line, feed_type):
                        iocs.append((line.lower(), feed_type))
        
        elif feed_format == 'zeek_intel':
            # Handle Zeek Intelligence format
            # Format: #fields indicator indicator_type meta.source meta.do_notice meta.desc
            # Skip header line
            header_found = False
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Skip header
                if line.startswith('#fields'):
                    header_found = True
                    continue
                
                # Skip comments
                if line.startswith('#'):
                    continue
                
                # Parse tab-separated values
                parts = line.split('\t')
                if len(parts) >= 2:
                    indicator = parts[0].strip()
                    indicator_type = parts[1].strip()
                    
                    # Map Zeek types to our types
                    if indicator_type == 'Intel::ADDR':
                        ioc_type = 'ip_address'
                    elif indicator_type == 'Intel::DOMAIN':
                        ioc_type = 'domain'
                    elif indicator_type == 'Intel::FILE_HASH':
                        ioc_type = 'file_hash'
                    else:
                        # Try to detect type if unknown
                        ioc_type = self._detect_ioc_type(indicator)
                    
                    if ioc_type and self._validate_ioc(indicator, ioc_type):
                        iocs.append((indicator.lower(), ioc_type))
        
        elif feed_format == 'csv':
            # Handle CSV format (simplified - could use csv module for complex cases)
            import csv
            from io import StringIO
            
            reader = csv.DictReader(StringIO(content))
            domain_column = feed.get('domain_column', 'domain')
            
            for row in reader:
                if domain_column in row:
                    value = row[domain_column]
                    # Extract domain from URL if needed
                    if value.startswith(('http://', 'https://')):
                        from urllib.parse import urlparse
                        parsed = urlparse(value)
                        value = parsed.netloc
                    
                    if self._validate_ioc(value, feed_type):
                        iocs.append((value.lower(), feed_type))
        
        elif feed_format == 'json':
            # Handle JSON format
            try:
                data = json.loads(content)
                ioc_field = feed.get('ioc_field', 'ioc')
                ioc_type_field = feed.get('ioc_type_field')
                
                # Handle both list and dict responses
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    # Support nested paths like "results.indicators"
                    data_field = feed.get('data_field', 'data')
                    if '.' in data_field:
                        # Navigate nested structure
                        current = data
                        for part in data_field.split('.'):
                            current = current.get(part, [])
                            if not isinstance(current, (dict, list)):
                                break
                        items = current if isinstance(current, list) else []
                    else:
                        items = data.get(data_field, [])
                else:
                    items = []
                
                for item in items:
                    if isinstance(item, dict) and ioc_field in item:
                        value = item[ioc_field]
                        
                        # Handle ThreatFox format with port numbers
                        if ':' in value and feed_type == 'mixed':
                            # Extract IP or domain from "ip:port" or "domain:port"
                            base_value = value.split(':')[0]
                            # Detect if it's an IP or domain
                            detected_type = self._detect_ioc_type(base_value)
                            if detected_type:
                                iocs.append((base_value.lower(), detected_type))
                        else:
                            # Determine IOC type
                            if ioc_type_field and ioc_type_field in item:
                                # Map ThreatFox types to our types
                                threatfox_type = item[ioc_type_field]
                                if threatfox_type in ['md5_hash', 'sha1_hash', 'sha256_hash']:
                                    actual_type = 'file_hash'
                                elif threatfox_type == 'ip:port':
                                    actual_type = 'ip_address'
                                elif threatfox_type == 'domain:port':
                                    actual_type = 'domain'
                                else:
                                    actual_type = threatfox_type
                                
                                if self._validate_ioc(value, actual_type):
                                    iocs.append((value.lower(), actual_type))
                            elif feed_type == 'mixed':
                                # Auto-detect type
                                detected_type = self._detect_ioc_type(value)
                                if detected_type:
                                    iocs.append((value.lower(), detected_type))
                            else:
                                # Use configured type
                                if self._validate_ioc(value, feed_type):
                                    iocs.append((value.lower(), feed_type))
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON from {feed['name']}")
        
        elif feed_format == 'hosts':
            # Handle hosts file format (e.g., "127.0.0.1 domain.com")
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    ip_part = parts[0]
                    domain_part = parts[1]
                    
                    # Skip localhost entries
                    if ip_part in ['127.0.0.1', '0.0.0.0', '::1']:
                        if domain_part not in ['localhost', 'localhost.localdomain']:
                            # This is a sinkholed domain
                            if self._validate_ioc(domain_part, 'domain'):
                                iocs.append((domain_part.lower(), 'domain'))
                    else:
                        # Both IP and domain might be malicious
                        if feed_type == 'mixed':
                            if self._validate_ioc(ip_part, 'ip_address'):
                                iocs.append((ip_part, 'ip_address'))
                            if self._validate_ioc(domain_part, 'domain'):
                                iocs.append((domain_part.lower(), 'domain'))
                        elif feed_type == 'domain':
                            if self._validate_ioc(domain_part, 'domain'):
                                iocs.append((domain_part.lower(), 'domain'))
                        elif feed_type == 'ip_address':
                            if self._validate_ioc(ip_part, 'ip_address'):
                                iocs.append((ip_part, 'ip_address'))
        
        elif feed_format == 'url_list':
            # Extract domains from URLs
            from urllib.parse import urlparse
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    parsed = urlparse(line)
                    domain = parsed.netloc.lower()
                    if domain:
                        # Remove port if present
                        if ':' in domain:
                            domain = domain.split(':')[0]
                        
                        # Check if it's an IP or domain
                        if self._validate_ioc(domain, 'ip_address'):
                            iocs.append((domain, 'ip_address'))
                        elif self._validate_ioc(domain, 'domain'):
                            iocs.append((domain, 'domain'))
                except:
                    continue
        
        return iocs
    
    def _detect_ioc_type(self, value: str) -> Optional[str]:
        """Detect the type of an IOC"""
        value = value.strip()
        
        # Check for IP address
        if self.patterns['ip_address'].match(value):
            return 'ip_address'
        
        # Check for file hash
        for hash_type, pattern in self.patterns['file_hash'].items():
            if pattern.match(value):
                return 'file_hash'
        
        # Check for domain (more lenient than full validation)
        if '.' in value and not value.startswith('.') and not value.endswith('.'):
            # Basic domain check - has dots, doesn't start/end with dot
            if not any(char in value for char in ['/', '\\', ' ', '@', ':']):
                return 'domain'
        
        return None
    
    def _validate_ioc(self, value: str, ioc_type: str) -> bool:
        """Validate an IOC against expected type"""
        value = value.strip()
        
        if ioc_type == 'ip_address':
            return bool(self.patterns['ip_address'].match(value))
        
        elif ioc_type == 'domain':
            # More lenient domain validation for feeds
            if not value or '.' not in value:
                return False
            # Skip if contains invalid characters
            if any(char in value for char in ['/', '\\', ' ', '@', ':', '[', ']']):
                return False
            # Skip common non-domains
            if value in ['localhost', '127.0.0.1', '0.0.0.0']:
                return False
            return True
        
        elif ioc_type == 'file_hash':
            for hash_type, pattern in self.patterns['file_hash'].items():
                if pattern.match(value):
                    return True
            return False
        
        return False
    
    def _store_iocs(self, iocs: List[Tuple[str, str]], source: str) -> int:
        """Store IOCs in the database"""
        if not iocs:
            return 0
        
        stored_count = 0
        batch = []
        batch_size = self.config['settings']['batch_size']
        
        for ioc_value, ioc_type in iocs:
            batch.append({
                'value': ioc_value,
                'entity_type': ioc_type,
                'source': source,  # Just use the feed name directly
                'confidence': 0.8  # High confidence for curated feeds
            })
            
            if len(batch) >= batch_size:
                stored_count += self._insert_batch(batch)
                batch = []
        
        # Insert remaining
        if batch:
            stored_count += self._insert_batch(batch)
        
        return stored_count
    
    def _insert_batch(self, batch: List[Dict]) -> int:
        """Insert a batch of IOCs"""
        inserted = 0
        
        for ioc in batch:
            try:
                # Check if IOC already exists (using value, not normalized_value for unique constraint)
                result = self.session.execute(text("""
                    SELECT id, occurrence_count, is_ioc_feed
                    FROM cluster.entities
                    WHERE value = :value
                    AND entity_type = :entity_type
                    LIMIT 1
                """), {
                    'value': ioc['value'],
                    'entity_type': ioc['entity_type']
                }).fetchone()
                
                if result:
                    # Update existing entity
                    self.session.execute(text("""
                        UPDATE cluster.entities
                        SET occurrence_count = occurrence_count + 1,
                            is_ioc_feed = TRUE,
                            ioc_source = :source,
                            updated_at = NOW(),
                            metadata = jsonb_set(
                                COALESCE(metadata, '{}'::jsonb),
                                '{last_seen_in_feed}',
                                to_jsonb(:timestamp ::text)
                            )
                        WHERE id = :id
                    """), {
                        'id': result.id,
                        'source': ioc['source'],
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    self.stats['iocs_updated'] += 1
                else:
                    # Insert new entity
                    # For domains and IPs, keep the original case but normalize for uniqueness
                    display_value = ioc['value']
                    if ioc['entity_type'] == 'domain':
                        # Domains should be lowercase for normalization
                        normalized = ioc['value'].lower()
                    else:
                        # IPs and hashes stay as-is
                        normalized = ioc['value']
                        display_value = ioc['value']
                    
                    self.session.execute(text("""
                        INSERT INTO cluster.entities 
                        (value, normalized_value, entity_type, occurrence_count, 
                         is_predefined, is_auto_extracted, is_ioc_feed, ioc_source, 
                         confidence_score, metadata, created_at, updated_at)
                        VALUES 
                        (:value, :normalized_value, :entity_type, 1,
                         FALSE, FALSE, TRUE, :source, :confidence,
                         jsonb_build_object(
                            'source', :source,
                            'first_seen_in_feed', :timestamp
                         ),
                         NOW(), NOW())
                        ON CONFLICT (value, entity_type) DO UPDATE
                        SET occurrence_count = entities.occurrence_count + 1,
                            is_ioc_feed = TRUE,
                            ioc_source = EXCLUDED.ioc_source,
                            metadata = entities.metadata || jsonb_build_object(
                                'last_seen_in_feed', EXCLUDED.metadata->>'first_seen_in_feed',
                                'sources', jsonb_build_array(entities.ioc_source, EXCLUDED.ioc_source)
                            ),
                            updated_at = NOW()
                    """), {
                        'value': display_value,
                        'normalized_value': normalized,
                        'entity_type': ioc['entity_type'],
                        'source': ioc['source'],
                        'confidence': ioc['confidence'],
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    self.stats['iocs_added'] += 1
                    inserted += 1
                    
                # Commit after each successful insert to avoid transaction issues
                self.session.commit()
                    
            except Exception as e:
                error_msg = str(e)
                if 'duplicate key value violates unique constraint' in error_msg:
                    logger.debug(f"IOC {ioc['value']} ({ioc['entity_type']}) already exists, skipping")
                elif 'violates check constraint' in error_msg:
                    logger.error(f"Constraint violation for IOC {ioc['value']}: {error_msg}")
                else:
                    logger.error(f"Failed to insert IOC {ioc['value']}: {e}")
                self.stats['errors'] += 1
                # Rollback the failed transaction
                self.session.rollback()
        
        return inserted
    
    def cleanup_old_iocs(self, days: int = 30):
        """Remove IOCs not seen in feeds for specified days"""
        logger.info(f"Cleaning up IOCs not seen in feeds for {days} days")
        
        try:
            result = self.session.execute(text("""
                DELETE FROM cluster.entities
                WHERE is_ioc_feed = TRUE
                AND is_predefined = FALSE
                AND occurrence_count < 5
                AND updated_at < NOW() - INTERVAL ':days days'
                AND NOT EXISTS (
                    SELECT 1 FROM cluster.article_entities ae
                    WHERE ae.entity_id = entities.id
                )
                RETURNING id
            """), {'days': days})
            
            deleted_count = result.rowcount
            self.session.commit()
            
            logger.info(f"Deleted {deleted_count} stale IOCs")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old IOCs: {e}")
            self.session.rollback()
            return 0


async def main():
    """Test the IOC ingester"""
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    
    from database_connection import DatabaseConnection
    
    # Initialize database connection
    db = DatabaseConnection()
    session = db.get_session()
    
    # Create ingester
    ingester = IOCIngester(session)
    
    # Run ingestion
    stats = await ingester.ingest_all_feeds()
    print(f"Ingestion complete: {stats}")
    
    # Cleanup old IOCs
    deleted = ingester.cleanup_old_iocs(days=30)
    print(f"Cleaned up {deleted} old IOCs")
    
    session.close()


if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Entity validation and cleaning for better clustering
Fixes poor entity extraction at the clustering stage
"""

import re
from typing import Dict, Set, List, Tuple, Optional
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class EntityValidator:
    """Validates and cleans entities to prevent bad clustering decisions"""
    
    def __init__(self, session: Optional[Session] = None):
        self.session = session
        self._entity_cache = None
        self._load_entities_from_db()
        
        # Patterns that indicate bad victim extraction
        self.bad_victim_patterns = [
            # Sentence fragments
            r'^(an?|the|that|which|who|what|where|when|why|how)\s+',
            r'\s+(was|were|is|are|has|have|had|been)\s*$',
            r'\s+(in|on|at|to|from|by|with|for|of|and|or)\s*$',
            
            # Contains verbs indicating actions
            r'\b(attack|breach|hack|steal|encrypt|leak|expose|compromise|infect|deploy|use|target|strike|hit|paralyzed?|lies?|represent)\b',
            
            # Too long (likely a sentence)
            r'^.{60,}$',
            
            # Contains punctuation that suggests it's not a proper entity
            r'[,;:]',
            
            # Starts with lowercase (except known companies)
            r'^[a-z]',
            
            # Common junk phrases
            r'(victims?|users?|customers?|employees?|data|information|systems?|networks?|computers?|accounts?|sites?|methods?)\s*$',
            r'^(millions?|thousands?|hundreds?|more)\s+(?:of\s+)?',
            r'(ransomware|malware|virus|trojan|worm|backdoor)\s+(attack|campaign|operation)',
            
            # New patterns for common false positives
            r'^(various|several|multiple|many|some|other)\s+',
            r'(mechanism|vulnerability|core|lovers?|process|service|feature)\s*',
            r'^to\s+various\s+',
            r'websites?\s*$',
            r'printing\s+and\s*$',
            
            # Fragments that end mid-sentence
            r'\s+(mechanism|vulnerability).*(?:lies|is|are)\s*$',
            r'lovers?\s+of\s+.*clothes',
        ]
        
        # Product/company aliases (these can be hard-coded as they're transformations, not entities)
        self.entity_aliases = {
            'matlab': 'mathworks',
            'mathworks': 'mathworks',
            'microsoft windows': 'windows',
            'ms windows': 'windows',
            'google chrome': 'chrome',
            'mozilla firefox': 'firefox',
            'apple safari': 'safari',
            'clickfix': 'clickfix',
            'eddie stealer': 'eddiestealer',
            'eddiestealer': 'eddiestealer',
            'lumma stealer': 'lumma',
            'lumma c2': 'lumma',
            'lummac2': 'lumma',
        }
    
    def _load_entities_from_db(self):
        """Load entities from database into cache"""
        self._entity_cache = {
            'ransomware_group': set(),
            'malware_family': set(),
            'apt_group': set(),
            'company': set(),
            'other': set()
        }
        
        if not self.session:
            logger.warning("No database session provided, entity validation will be limited")
            return
        
        try:
            # Load all predefined entities and frequently seen entities
            result = self.session.execute(text("""
                SELECT LOWER(value) as value, entity_type 
                FROM cluster.entities 
                WHERE entity_type IN ('ransomware_group', 'malware_family', 'apt_group', 'company', 'other')
                AND (is_predefined = TRUE OR occurrence_count > 5)
            """))
            
            for row in result:
                if row.entity_type in self._entity_cache:
                    self._entity_cache[row.entity_type].add(row.value)
            
            logger.info(f"Loaded {sum(len(v) for v in self._entity_cache.values())} entities from database")
            
        except Exception as e:
            logger.error(f"Failed to load entities from database: {e}")
    
    def refresh_cache(self):
        """Refresh the entity cache from database"""
        self._load_entities_from_db()
    
    def is_known_threat_actor(self, value: str) -> bool:
        """Check if value is a known threat actor (ransomware, malware, APT)"""
        value_lower = value.lower()
        return (value_lower in self._entity_cache.get('ransomware_group', set()) or
                value_lower in self._entity_cache.get('malware_family', set()) or
                value_lower in self._entity_cache.get('apt_group', set()))
    
    def is_known_company(self, value: str) -> bool:
        """Check if value is a known company"""
        value_lower = value.lower()
        # Check database entities
        if value_lower in self._entity_cache.get('company', set()):
            return True
        # Also check common variations that might start with lowercase
        lowercase_companies = {'ebay', 'iphone', 'ipad', 'ipod', 'itunes', 'icloud', 'eharmony', 'etrade', 'easyjet'}
        return value_lower in lowercase_companies
    
    def clean_entities(self, entities: Dict[str, Set]) -> Dict[str, Set]:
        """Clean and validate all entities"""
        cleaned = {}
        
        for entity_type, values in entities.items():
            cleaned_values = set()
            
            for value in values:
                if entity_type == 'other':
                    cleaned_value = self._clean_other_entity(value)
                elif entity_type == 'company':
                    cleaned_value = self._clean_company(value)
                elif entity_type in ['malware_family', 'ransomware_group', 'apt_group']:
                    cleaned_value = self._clean_threat_actor(value)
                else:
                    cleaned_value = self._clean_generic(value)
                
                if cleaned_value:
                    # Apply aliases
                    cleaned_value = self.entity_aliases.get(cleaned_value.lower(), cleaned_value)
                    cleaned_values.add(cleaned_value)
            
            if cleaned_values:
                cleaned[entity_type] = cleaned_values
        
        return cleaned
    
    def _clean_other_entity(self, value: str) -> str:
        """Clean victim organization entities"""
        if not value or not isinstance(value, str):
            return ""
        
        value = value.strip()
        value_lower = value.lower()
        
        # Skip if it's a known threat actor
        if self.is_known_threat_actor(value):
            logger.debug(f"Skipping victim '{value}' - it's a threat actor")
            return ""
        
        # Check against bad patterns
        for pattern in self.bad_victim_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.debug(f"Skipping victim '{value}' - matches bad pattern")
                return ""
        
        # Skip if too short or too long
        if len(value) < 3 or len(value) > 50:
            logger.debug(f"Skipping victim '{value}' - bad length")
            return ""
        
        # Must start with uppercase (unless known company)
        if not value[0].isupper() and not self.is_known_company(value):
            logger.debug(f"Skipping victim '{value}' - doesn't start with uppercase")
            return ""
        
        # Extract company name from phrases like "X confirms breach"
        company_match = re.match(r'^([A-Z][A-Za-z0-9\s&\'-]+?)\s+(?:confirms?|reports?|discloses?|announces?|says?)', value)
        if company_match:
            return company_match.group(1).strip()
        
        return value
    
    def _clean_company(self, value: str) -> str:
        """Clean company entities"""
        if not value or not isinstance(value, str):
            return ""
        
        value = value.strip()
        
        # Remove common suffixes
        value = re.sub(r'\s*(Inc\.?|LLC|Ltd\.?|Corp\.?|Corporation|Company|Co\.?)$', '', value, flags=re.IGNORECASE)
        
        # Skip if too short
        if len(value) < 2:
            return ""
        
        return value
    
    def _clean_threat_actor(self, value: str) -> str:
        """Clean threat actor entities (malware, ransomware, APT)"""
        if not value or not isinstance(value, str):
            return ""
        
        value = value.strip()
        
        # Remove "ransomware" suffix
        value = re.sub(r'\s+ransomware$', '', value, flags=re.IGNORECASE)
        
        # Remove version numbers for consistency
        value = re.sub(r'\s+v?\d+(\.\d+)*$', '', value)
        
        return value
    
    def _clean_generic(self, value: str) -> str:
        """Generic entity cleaning"""
        if not value or not isinstance(value, str):
            return ""
        
        value = value.strip()
        
        # Skip if too long (likely a sentence)
        if len(value) > 100:
            return ""
        
        return value
    
    def merge_related_entities(self, entities: Dict[str, Set]) -> Dict[str, Set]:
        """Merge entities that are related or aliases"""
        merged = {}
        
        for entity_type, values in entities.items():
            merged_values = set()
            
            # Group values by their canonical form
            canonical_groups = {}
            for value in values:
                canonical = self._get_canonical_form(value, entity_type)
                if canonical not in canonical_groups:
                    canonical_groups[canonical] = []
                canonical_groups[canonical].append(value)
            
            # Use the shortest/most common form as the representative
            for canonical, group in canonical_groups.items():
                if len(group) == 1:
                    merged_values.add(group[0])
                else:
                    # Use the shortest form
                    representative = min(group, key=len)
                    merged_values.add(representative)
            
            if merged_values:
                merged[entity_type] = merged_values
        
        return merged
    
    def _get_canonical_form(self, value: str, entity_type: str) -> str:
        """Get canonical form of an entity for grouping"""
        value_lower = value.lower()
        
        # Check aliases first
        if value_lower in self.entity_aliases:
            return self.entity_aliases[value_lower]
        
        # For companies, normalize common variations
        if entity_type == 'company':
            # Microsoft Windows -> Microsoft
            if 'microsoft' in value_lower and 'windows' in value_lower:
                return 'microsoft'
            # Google Chrome -> Google
            if 'google' in value_lower and 'chrome' in value_lower:
                return 'google'
        
        # For malware, handle variations
        if entity_type in ['malware_family', 'ransomware_group']:
            # LockBit 2.0 -> lockbit
            base = re.sub(r'\s*\d+(\.\d+)*$', '', value_lower)
            return base
        
        return value_lower
    
    def validate_entity_relationships(self, entities1: Dict[str, Set], 
                                    entities2: Dict[str, Set]) -> Tuple[bool, str]:
        """Validate if two sets of entities have valid relationships"""
        
        # Check for impossible combinations
        malware1 = entities1.get('malware_family', set()) | entities1.get('ransomware_group', set())
        malware2 = entities2.get('malware_family', set()) | entities2.get('ransomware_group', set())
        
        # Different ransomware groups attacking the same victim is suspicious
        if malware1 and malware2 and not (malware1 & malware2):
            victims1 = entities1.get('other', set())
            victims2 = entities2.get('other', set())
            
            if victims1 and victims2 and (victims1 & victims2):
                # Check if they're related groups from database
                malware1_lower = {m.lower() for m in malware1}
                malware2_lower = {m.lower() for m in malware2}
                
                # Query database for related groups if session available
                if self.session:
                    try:
                        # Check if any of the malware groups share aliases
                        result = self.session.execute(text("""
                            SELECT DISTINCT e1.value, e2.value
                            FROM cluster.entities e1
                            JOIN cluster.entities e2 ON e1.normalized_value = e2.normalized_value
                            WHERE e1.entity_type IN ('ransomware_group', 'malware_family')
                            AND e2.entity_type IN ('ransomware_group', 'malware_family')
                            AND LOWER(e1.value) = ANY(:malware1)
                            AND LOWER(e2.value) = ANY(:malware2)
                        """), {
                            'malware1': list(malware1_lower),
                            'malware2': list(malware2_lower)
                        })
                        
                        if result.rowcount > 0:
                            return True, "Related malware groups"
                    except Exception as e:
                        logger.error(f"Failed to check related groups: {e}")
                
                # Fallback to known related groups
                related_groups = [
                    {'conti', 'trickbot'},
                    {'alphv', 'blackcat'},
                    {'sodinokibi', 'revil'},
                ]
                
                is_related = any(
                    malware1_lower.intersection(group) and malware2_lower.intersection(group)
                    for group in related_groups
                )
                
                if not is_related:
                    return False, f"Different ransomware groups ({malware1} vs {malware2}) attacking same victim"
        
        return True, "Valid relationship"
#!/usr/bin/env python3
"""
Unified Entity Extraction Module
Consolidates all entity extraction logic from fetch.py and entity_refresh.py
"""

import re
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import logging
from functools import lru_cache
import spacy

logger = logging.getLogger(__name__)


class EntityExtractor:
    """Consolidated entity extraction with all patterns and logic in one place"""
    
    def __init__(self, session=None):
        self.session = session
        self._entity_cache = {}
        self._pattern_cache = {}
        
        # Initialize SpaCy if available
        try:
            self.nlp = spacy.load("en_core_web_sm")
            self.has_spacy = True
            logger.info("SpaCy NER model loaded successfully")
        except:
            self.nlp = None
            self.has_spacy = False
            logger.warning("SpaCy not available - using regex patterns only")
        
        # Initialize all patterns
        self._init_patterns()
        self._load_entities_from_db()
    
    def _init_patterns(self):
        """Initialize all regex patterns for entity extraction"""
        
        # Technical indicator patterns
        self.patterns = {
            'cve': re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|io|co|uk|de|fr|jp|au|us|ru|ch|it|nl|se|no|es|mil|info|biz|name|ly|tv|cc|me|tk|ml|ga|cf)\b', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'registry_key': re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\\A-Za-z0-9_\-\.]+'),
            'file_path_windows': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
            'file_path_unix': re.compile(r'\/(?:[^\/\0]+\/)*[^\/\0]+'),
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'mitre_technique': re.compile(r'\b[TS]\d{4}(?:\.\d{3})?\b'),
            # Campaign extraction disabled - should be populated via predefined lists
            # 'campaign': re.compile(r'(?:campaign|operation)\s+(?:dubbed|named|called|known\s+as)\s*["\']?([A-Z][A-Za-z0-9\s]{2,20})["\']?', re.IGNORECASE),
            'bounty_amount': re.compile(r'\$([0-9,]+(?:\.[0-9]+)?)\s*(?:million|M|billion|B)?\s*(?:bounty|reward)', re.IGNORECASE),
        }
        
        # Threat actor discovery patterns - DISABLED for dynamic extraction
        # These entities should be populated via predefined lists instead
        self.discovery_patterns = {}
        
        # Keeping the old patterns commented for reference
        # self.discovery_patterns = {
        #     'ransomware_group': [...],
        #     'apt_group': [...],
        #     'malware_family': [...]
        # }
        
        # Victim organization patterns - Enhanced for better company detection
        self.victim_patterns = [
            # Standard breach patterns
            re.compile(r'(?:breach(?:ed)?|hack(?:ed)?|compromise[d]?|attack(?:ed)?|target(?:ed)?)\s+(?:at\s+)?([A-Z][A-Za-z0-9\s&\-\.]{2,40})(?=\s+(?:in|on|by|for)\s)', re.IGNORECASE),
            re.compile(r'\b([A-Z][A-Za-z0-9\s&\-\.]{2,40})\s+(?:was|were)\s+(?:breach|hack|compromise|attack|target)', re.IGNORECASE),
            re.compile(r'(?:victim|target)s?\s+(?:include[ds]?|are|were)?\s*:?\s*([A-Z][A-Za-z0-9\s&\-\.,]{2,40})(?=[,;]|\s+and\s+)', re.IGNORECASE),
            re.compile(r'\b([A-Z][A-Za-z0-9\s&\-\.]{2,40})\s+(?:suffer|experience|report|confirm|disclose)[eds]?\s+(?:a\s+)?(?:breach|attack|incident)', re.IGNORECASE),
            re.compile(r'\b([A-Z][A-Za-z0-9\s&\-\.]{2,40})\s+(?:hit|infected|encrypted)\s+(?:by|with)\s+ransomware', re.IGNORECASE),
            re.compile(r'ransomware\s+(?:hit|attack|target)[eds]?\s+([A-Z][A-Za-z0-9\s&\-\.]{2,40})(?=[\s,\.]|$)', re.IGNORECASE),
            re.compile(r'ransomware\s+that\s+(?:hit|attacked|targeted|infected)\s+([A-Z][A-Za-z0-9\s&\-\.\']{2,40})(?=[\s,\.]|$)', re.IGNORECASE),
            re.compile(r'strikes\s+(?:an?\s+)?([A-Z]{3,8})(?=\s+[^a-zA-Z]|$)', re.IGNORECASE),
            # New patterns for better company detection
            re.compile(r'\b([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*(?:\s+(?:Health|Healthcare|Medical|Center|Hospital|Systems?|Corp|Corporation|Inc|LLC|Ltd|Group|Networks?|Technologies|Services|Solutions|Software|Bank|Financial|University|College|School))?)\s+(?:confirms?|acknowledges?|announces?|reveals?|reports?|discloses?)', re.IGNORECASE),
            re.compile(r'(?:disrupts?|impacts?|affects?)\s+(?:operations?\s+at\s+)?([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*(?:\s+(?:Health|Healthcare|Medical|Center|Hospital|Systems?|Corp|Corporation|Inc|LLC|Ltd|Group|Networks?|Technologies|Services|Solutions|Software|Bank|Financial|University|College|School))?)', re.IGNORECASE),
            re.compile(r'(?:patient|customer|employee|user)\s+(?:data|information|records?)\s+(?:from|at|of)\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*)', re.IGNORECASE),
        ]
        
        # Known false positives
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
            },
            'victim': {
                'The', 'A', 'An', 'New', 'Security', 'Cyber', 'Data', 'Network',
                'Researchers', 'Experts', 'Hackers', 'Attackers', 'Threat',
                'FBI', 'NSA', 'CISA', 'DHS', 'Government', 'Agency', 'Department',
                'Company', 'Corporation', 'Inc', 'LLC', 'Group', 'Team',
                'Users', 'Customers', 'Victims', 'Organizations', 'Entities'
            }
        }
        
        # Generic terms to filter out
        self.generic_malware_terms = {
            'malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'botnet',
            'rat', 'spyware', 'adware', 'rootkit', 'keylogger', 'worm'
        }
        
        self.generic_attack_terms = {
            'attack', 'campaign', 'operation', 'activity', 'threat', 'incident'
        }
        
        # Cybersecurity-focused common domains to filter
        self.cybersecurity_common_domains = {
            # Major Security Organizations & Standards
            'cve.org', 'nvd.nist.gov', 'nist.gov', 'mitre.org', 'cwe.mitre.org',
            'cisa.gov', 'us-cert.gov', 'cert.org', 'first.org', 'sans.org',
            'owasp.org', 'iso.org', 'ietf.org', 'rfc-editor.org',
            
            # Security Vendors & Threat Intelligence
            'crowdstrike.com', 'fireeye.com', 'mandiant.com', 'recordedfuture.com',
            'symantec.com', 'mcafee.com', 'norton.com', 'kaspersky.com',
            'bitdefender.com', 'avast.com', 'avg.com', 'malwarebytes.com',
            'paloaltonetworks.com', 'fortinet.com', 'checkpoint.com', 'sophos.com',
            'trendmicro.com', 'f-secure.com', 'eset.com', 'webroot.com',
            'carbonblack.com', 'cylance.com', 'sentinelone.com', 'endgame.com',
            'tanium.com', 'rapid7.com', 'qualys.com', 'tenable.com',
            'veracode.com', 'checkmarx.com', 'whitesource.com', 'snyk.io',
            
            # Threat Intelligence Platforms & Feeds
            'virustotal.com', 'hybrid-analysis.com', 'any.run', 'joesandbox.com',
            'reversing.labs', 'inquest.net', 'otx.alienvault.com', 'abuse.ch',
            'malwarebazaar.abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
            'feodotracker.abuse.ch', 'sslbl.abuse.ch', 'spamhaus.org',
            'emergingthreats.net', 'proofpoint.com', 'mimecast.com',
            
            # Security Research & Blogs
            'krebsonsecurity.com', 'schneier.com', 'darkreadingnews.com',
            'securityweek.com', 'infosecurity-magazine.com', 'scmagazine.com',
            'csoonline.com', 'securityaffairs.co', 'bleepingcomputer.com',
            'threatpost.com', 'cyberscoop.com', 'securityboulevard.com',
            'securityonline.info', 'thehackernews.com', 'darkreading.com',
            
            # Cloud Security & DevSecOps
            'aquasec.com', 'twistlock.com', 'prismacloud.paloaltonetworks.com',
            'lacework.com', 'sysdig.com', 'falco.org', 'anchore.com',
            'sonarqube.org',
            
            # Major Browsers & OS (security updates)
            'mozilla.org', 'chromium.org', 'webkit.org', 'ubuntu.com',
            'redhat.com', 'debian.org', 'centos.org',
            
            # Common non-security domains
            'twitter.com', 'facebook.com', 'linkedin.com', 'youtube.com',
            'instagram.com', 'tiktok.com', 'snapchat.com',
            'netflix.com', 'spotify.com', 'twitch.com',
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com',
            'amazon.com', 'ebay.com', 'etsy.com', 'shopify.com',
            'apple.com', 'microsoft.com', 'google.com', 'github.com',
            
            # News and media sites
            'bloomberg.com', 'reuters.com', 'apnews.com', 'forbes.com',
            'techcrunch.com', 'wired.com', 'arstechnica.com', 'zdnet.com',
            'theverge.com', 'engadget.com', 'gizmodo.com', 'mashable.com',
            'kasperskycontenthub.com', 'media.kasperskycontenthub.com',
            
            # Government domains (dynamically filtered later for .gov)
            'fbi.gov', 'dhs.gov', 'state.gov', 'defense.gov', 'justice.gov',
            
            # Blogs and content platforms
            'medium.com', 'blogger.com', 'wordpress.com', 'substack.com',
            'blogspot.com', 'tumblr.com', 'ghost.io', 'msecureltd.blogspot.com',
            
            # Retail and e-commerce sites that might appear in breach articles
            'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
            'lowes.com', 'costco.com', 'samsclub.com', 'macys.com',
            'nordstrom.com', 'thenorthface.com', 'nike.com', 'adidas.com',
            
            # Common infrastructure
            'chromereleases.googleblog.com', 'www.cve.org',

            # Others to add
            'manageengine.com', '2fsecurityonline.info', 'github.io', '.gov', 'googleblog.com'
        }
        
        # Security-related subdomain patterns
        self.security_related_subdomains = {
            'security', 'cert', 'vuln', 'advisory', 'patch', 'update',
            'threat', 'intel', 'malware', 'phishing', 'breach', 'incident'
        }
    
    def _load_entities_from_db(self):
        """Load predefined entities from database"""
        self.known_entities = defaultdict(set)
        
        if not self.session:
            return
        
        try:
            from sqlalchemy import text
            result = self.session.execute(text("""
                SELECT value, entity_type 
                FROM cluster.entities 
                WHERE is_predefined = TRUE
            """))
            
            for row in result:
                self.known_entities[row.entity_type].add(row.value.lower())
            
            # Log entity counts by type
            for entity_type, values in self.known_entities.items():
                logger.info(f"Loaded {len(values)} {entity_type} entities")
            
            logger.info(f"Total: {sum(len(v) for v in self.known_entities.values())} predefined entities")
            
        except Exception as e:
            logger.error(f"Error loading entities from database: {e}")
    
    def extract_all(self, text: str, use_enhanced: bool = True, source_url: str = None) -> Dict[str, List[str]]:
        """
        Main extraction method - extracts all entity types
        
        Args:
            text: Text to extract from
            use_enhanced: Whether to use enhanced extraction with NER
            source_url: URL of the article source (used to filter out self-references)
            
        Returns:
            Dictionary of entity_type -> list of values
        """
        # Clean text from common HTML artifacts before extraction
        text = self._clean_text_from_html(text)
        
        # Normalize defanged indicators
        text = self._normalize_defanged_text(text)
        
        # Check cache first
        text_hash = hash(text)
        cache_key = (text_hash, use_enhanced)
        if cache_key in self._entity_cache:
            return self._entity_cache[cache_key]
        
        entities = defaultdict(list)
        
        # Extract technical indicators
        entities.update(self._extract_technical_indicators(text, source_url))
        
        # Extract threat actors - only from predefined lists, not dynamic discovery
        # Dynamic discovery is disabled to avoid false positives
        # entities.update(self._extract_threat_actors(text))
        
        # Extract victim organizations
        victims = self._extract_victim_organizations(text)
        if victims:
            entities['other'] = victims
        
        # Extract known entities from predefined lists
        entities.update(self._extract_known_entities(text))
        
        # Use SpaCy NER if available and requested
        if use_enhanced and self.has_spacy:
            entities.update(self._extract_with_spacy(text))
        
        # Clean and deduplicate
        cleaned_entities = self._clean_entities(entities)
        
        # Cache result
        self._entity_cache[cache_key] = cleaned_entities
        if len(self._entity_cache) > 10000:
            # Clear oldest entries
            self._entity_cache.clear()
        
        return cleaned_entities
    
    def _extract_technical_indicators(self, text: str, source_url: str = None) -> Dict[str, List[str]]:
        """Extract technical IoCs"""
        entities = defaultdict(list)
        
        # CVEs
        entities['cve'] = list(set(self.patterns['cve'].findall(text)))
        
        # IP addresses with validation
        potential_ips = self.patterns['ip'].findall(text)
        valid_ips = []
        
        # Common IPs to exclude (localhost, private ranges, common examples)
        excluded_ips = {
            '127.0.0.1', '0.0.0.0', '255.255.255.255',
            '192.168.1.1', '192.168.0.1', '10.0.0.1',
            '8.8.8.8', '8.8.4.4', '1.1.1.1',  # Common DNS servers
        }
        
        # Private IP ranges to exclude
        private_ranges = [
            (10, 0, 0, 0, 10, 255, 255, 255),      # 10.0.0.0/8
            (172, 16, 0, 0, 172, 31, 255, 255),    # 172.16.0.0/12
            (192, 168, 0, 0, 192, 168, 255, 255),  # 192.168.0.0/16
        ]
        
        for ip in potential_ips:
            octets = ip.split('.')
            if len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets):
                # Skip if in excluded list
                if ip in excluded_ips:
                    continue
                    
                # Skip if in private ranges
                ip_nums = [int(o) for o in octets]
                is_private = False
                for start_a, start_b, start_c, start_d, end_a, end_b, end_c, end_d in private_ranges:
                    if (ip_nums[0] == start_a and 
                        start_b <= ip_nums[1] <= end_b):
                        is_private = True
                        break
                
                if not is_private:
                    valid_ips.append(ip)
                    
        entities['ip_address'] = list(set(valid_ips))
        
        # Domains with filtering
        raw_domains = self.patterns['domain'].findall(text)
        filtered_domains = self._filter_cybersec_domains(raw_domains, source_url)
        entities['domain'] = list(set(filtered_domains))
        
        # Email addresses (exclude personal email providers)
        raw_emails = self.patterns['email'].findall(text)
        filtered_emails = []
        personal_domains = [
            '@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com', 
            '@aol.com', '@icloud.com', '@mail.com', '@protonmail.com',
            '@ymail.com', '@live.com', '@msn.com', '@me.com'
        ]
        for email in raw_emails:
            email_lower = email.lower()
            if not any(domain in email_lower for domain in personal_domains):
                filtered_emails.append(email)
        entities['email'] = list(set(filtered_emails))
        
        # Hashes - all stored as 'file_hash' type
        hash_values = []
        hash_values.extend(self.patterns['md5'].findall(text))
        hash_values.extend(self.patterns['sha1'].findall(text))
        hash_values.extend(self.patterns['sha256'].findall(text))
        if hash_values:
            entities['file_hash'] = list(set(hash_values))
        
        # File paths (exclude URLs)
        file_paths = []
        # Windows paths
        for path in self.patterns['file_path_windows'].findall(text):
            if len(path) <= 200:
                file_paths.append(path)
        
        # Unix paths - be more selective to avoid URL paths
        for path in self.patterns['file_path_unix'].findall(text):
            # Skip if it looks like a URL path
            if any(url_indicator in path.lower() for url_indicator in [
                'http', '.com/', '.org/', '.net/', '.html', '.php', 
                'www.', '?', '&', '=', 'src=', 'googleblog'
            ]):
                continue
            
            # Only include if it's a real file path
            if len(path) <= 200 and (
                # Has file extension (but not web extensions)
                ('.' in path.split('/')[-1] and 
                 not any(path.endswith(ext) for ext in ['.html', '.htm', '.php', '.asp', '.jsp'])) or
                # Or is in a system directory
                any(d in path for d in ['/etc/', '/usr/', '/var/', '/opt/', '/home/', '/tmp/', '/bin/', '/sbin/'])
            ):
                file_paths.append(path)
        
        entities['file_path'] = list(set(file_paths))
        
        # MITRE techniques
        entities['mitre_technique'] = list(set(self.patterns['mitre_technique'].findall(text)))
        
        # Campaign extraction disabled - campaigns should be populated via predefined lists
        # to avoid false positives
        
        # Bounty/Reward amounts (useful for clustering bounty stories)
        bounty_matches = self.patterns['bounty_amount'].findall(text)
        if bounty_matches:
            entities['bounty_amount'] = list(set(bounty_matches))
        
        return dict(entities)
    
    def _extract_threat_actors(self, text: str) -> Dict[str, List[str]]:
        """Extract threat actor names - ONLY from predefined lists"""
        entities = defaultdict(set)
        
        # Only check against known predefined entities
        text_lower = text.lower()
        for entity_type in ['apt_group', 'ransomware_group', 'malware_family', 'campaign']:
            for known_entity in self.known_entities.get(entity_type, []):
                if known_entity in text_lower:
                    # Find the original case version
                    pattern = re.compile(r'\b' + re.escape(known_entity) + r'\b', re.IGNORECASE)
                    matches = pattern.findall(text)
                    if matches:
                        entities[entity_type].add(matches[0])
        
        # Dynamic discovery is disabled - entities should be populated via predefined lists
        
        return {k: list(v) for k, v in entities.items() if v}
    
    def _extract_victim_organizations(self, text: str) -> List[str]:
        """Extract victim organization names"""
        victims = set()
        
        # Build exclusion set
        known_threat_actors = set()
        for actors in self.known_entities.values():
            known_threat_actors.update(actors)
        
        threat_keywords = {'ransomware', 'malware', 'trojan', 'virus', 'apt', 'group'}
        
        # Extract using patterns
        for pattern in self.victim_patterns:
            matches = pattern.findall(text)
            for match in matches:
                victim = match.strip()
                
                # Clean up
                victim = re.sub(r'\s+(?:Would|Could|Should|Did|Has|Have|Is|Are|Was|Were|Will|Can|May|Might)\s.*$', '', victim, flags=re.IGNORECASE)
                victim = re.sub(r'\s*(?:Inc|Corp|Ltd|LLC|Company|Co)\s*\.?$', '', victim)
                
                # Validate
                victim_lower = victim.lower()
                
                # Skip if too short (unless known acronym)
                known_acronyms = {'MSP', 'NHS', 'FBI', 'CIA', 'NSA', 'DHS', 'DOD', 'MOD'}
                if len(victim) <= 3 and victim.upper() not in known_acronyms:
                    continue
                
                # Skip if it's a threat actor
                if victim_lower in known_threat_actors:
                    continue
                
                # Skip if contains threat keywords
                if any(keyword in victim_lower for keyword in threat_keywords):
                    continue
                
                # Skip common exclusions
                if victim in self.exclusions['victim']:
                    continue
                
                # Additional validation
                if len(victim) > 50 or '  ' in victim:
                    continue
                
                # Check for technical terms that indicate it's not an org
                tech_terms = [
                    'devices', 'credentials', 'systems', 'networks', 'servers', 'databases',
                    'to steal', 'to encrypt', 'to deploy', 'to infect', 'written in', 'dubbed',
                    'between', 'through', 'across', 'within', 'during', 'after', 'before',
                    'exploit', 'vector', 'payload', 'malicious', 'obfuscated'
                ]
                if any(term in victim_lower for term in tech_terms):
                    continue
                
                victims.add(victim)
        
        return list(victims)
    
    def _extract_with_spacy(self, text: str) -> Dict[str, List[str]]:
        """Extract entities using SpaCy NER"""
        entities = defaultdict(set)
        
        try:
            # Limit text length for performance
            doc = self.nlp(text[:5000])
            
            for ent in doc.ents:
                if ent.label_ == "ORG":
                    # Check context for victim organizations
                    sentence = ent.sent.text.lower()
                    breach_keywords = ['breach', 'hack', 'attack', 'compromise', 'victim', 'target', 'ransomware']
                    if any(keyword in sentence for keyword in breach_keywords):
                        org_lower = ent.text.lower()
                        if org_lower not in self.known_entities.get('ransomware_group', set()):
                            entities['other'].add(ent.text)
                    # REMOVED: Do NOT dynamically extract companies
                    # Companies should only come from the predefined list
                
                # REMOVED: Dynamic platform extraction
                # Platforms should only come from predefined lists
                # elif ent.label_ == "PRODUCT":
                #     entities['platform'].add(ent.text)
                
                elif ent.label_ == "NORP":  # Nationalities or religious/political groups
                    if any(word in ent.text.lower() for word in ['apt', 'group']):
                        entities['apt_group'].add(ent.text)
        
        except Exception as e:
            logger.debug(f"SpaCy extraction error: {e}")
        
        return {k: list(v) for k, v in entities.items() if v}
    
    def _clean_entities(self, entities: Dict[str, List]) -> Dict[str, List]:
        """Clean and validate extracted entities"""
        cleaned = {}
        
        for entity_type, values in entities.items():
            cleaned_values = []
            
            for value in values:
                if not value or not isinstance(value, str):
                    continue
                
                value = value.strip()
                
                # Type-specific cleaning
                if entity_type == 'other':  # Victim organizations
                    if len(value) >= 3 and len(value) <= 50 and value[0].isupper():
                        cleaned_values.append(value)
                
                elif entity_type in ['ransomware_group', 'malware_family']:
                    # Remove version numbers
                    cleaned_value = re.sub(r'\s+v?\d+(\.\d+)*$', '', value)
                    if cleaned_value and cleaned_value not in self.generic_malware_terms:
                        cleaned_values.append(cleaned_value)
                
                elif entity_type == 'company':
                    # Remove company suffixes
                    cleaned_value = re.sub(r'\s*(Inc\.?|LLC|Ltd\.?|Corp\.?|Corporation|Company|Co\.?)$', '', value, flags=re.IGNORECASE)
                    if len(cleaned_value) >= 2:
                        cleaned_values.append(cleaned_value)
                
                else:
                    # Default: just ensure reasonable length
                    if len(value) <= 200:
                        cleaned_values.append(value)
            
            if cleaned_values:
                # Remove duplicates while preserving order
                seen = set()
                unique_values = []
                for v in cleaned_values:
                    if v.lower() not in seen:
                        seen.add(v.lower())
                        unique_values.append(v)
                
                cleaned[entity_type] = unique_values
        
        return cleaned
    
    def extract_enhanced(self, text: str, title: str = "") -> Dict:
        """
        Enhanced extraction with metadata (for compatibility with existing code)
        """
        entities = self.extract_all(text + " " + title)
        
        # Add metadata
        content_type = self._classify_content_type(title, text)
        temporal = self._extract_temporal_indicators(text)
        
        return {
            'entities': entities,
            'content_type': content_type,
            'temporal': temporal,
            'entity_weights': {}  # Placeholder for compatibility
        }
    
    def _classify_content_type(self, title: str, content: str) -> str:
        """Classify content type"""
        text = f"{title} {content[:500]}".lower()
        
        if any(word in text for word in ['breaking', 'just in', 'developing', 'urgent', 'alert']):
            return "breaking"
        elif any(word in text for word in ['update', 'follow-up', 'additional details', 'previously']):
            return "update"
        elif any(word in text for word in ['analysis', 'research', 'study', 'report', 'whitepaper']):
            return "analysis"
        else:
            return "news"
    
    def _extract_temporal_indicators(self, text: str) -> Dict:
        """Extract temporal indicators"""
        indicators = {
            'is_recent': False,
            'has_date': False,
            'time_references': []
        }
        
        recent_patterns = [
            r'\b(?:today|yesterday|this\s+(?:morning|afternoon|evening|week))\b',
            r'\b(?:just|recently|moments?\s+ago|hours?\s+ago)\b',
            r'\b(?:ongoing|developing|breaking)\b'
        ]
        
        for pattern in recent_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators['is_recent'] = True
                break
        
        # Date patterns
        date_pattern = r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b'
        date_matches = re.findall(date_pattern, text)
        if date_matches:
            indicators['has_date'] = True
            indicators['time_references'] = date_matches
        
        return indicators
    
    def _filter_cybersec_domains(self, raw_domains: List[str], source_url: str = None) -> List[str]:
        """Filter domains but keep cybersecurity-relevant ones"""
        filtered_domains = []
        
        # Extract source domain from URL if provided
        source_domain = None
        if source_url:
            from urllib.parse import urlparse
            parsed = urlparse(source_url)
            source_domain = parsed.netloc.lower()
            if source_domain.startswith('www.'):
                source_domain = source_domain[4:]
        
        for domain in raw_domains:
            domain = domain.lower().strip()
            
            # Skip if empty or too short/long
            if len(domain) < 4 or len(domain) > 200:
                continue
                
            # Skip if it contains HTML artifacts or paths
            if any(char in domain for char in ['<', '>', '"', "'", '[', ']', '/']):
                continue
                
            # Skip if it's a path, not a domain
            if domain.startswith('/') or '"/>' in domain:
                continue
                
            # Skip if it's the article's source domain
            if domain == source_domain:
                continue
                
            # Skip all .gov domains (they're usually mentioned, not compromised)
            if domain.endswith('.gov'):
                continue
                
            # Skip if in cybersecurity common domains list
            if domain in self.cybersecurity_common_domains:
                continue
                
            # Skip if it's a subdomain of a cybersecurity common domain
            if any(domain.endswith(f'.{common}') for common in self.cybersecurity_common_domains):
                continue
                
            # Keep domains that might be security-related based on subdomain
            parts = domain.split('.')
            if len(parts) > 2 and parts[0] in self.security_related_subdomains:
                # This might be a security-related subdomain, so keep it
                filtered_domains.append(domain)
                continue
            
            # Skip if it matches known patterns (social media, entertainment, etc.)
            if self._is_likely_non_security_domain(domain):
                continue
                
            # Additional validation
            if self._is_valid_domain_format(domain):
                filtered_domains.append(domain)
        
        return filtered_domains
    
    def _is_likely_non_security_domain(self, domain: str) -> bool:
        """Check if domain is likely non-security related"""
        non_security_patterns = [
            # Social media that's not security-focused
            r'.*\.(facebook|instagram|tiktok|snapchat)\.com',
            # Entertainment
            r'.*\.(netflix|spotify|youtube|twitch)\.com',
            # E-commerce (unless it's a compromised site report)
            r'.*\.(amazon|ebay|etsy|shopify)\.com',
            # News sites (unless security-focused)
            r'.*\.(cnn|bbc|nytimes|washingtonpost)\.com',
            # Common CDNs and infrastructure
            r'.*\.(cloudfront|fastly|akamai|cloudflare)\.(net|com)',
            # Analytics and tracking
            r'.*\.(google-analytics|googletagmanager|doubleclick|segment)\.com',
            # Ad networks
            r'.*\.(googlesyndication|adsystem|adnxs|adzerk|outbrain)\.com',
        ]
        
        return any(re.match(pattern, domain) for pattern in non_security_patterns)
    
    def _is_valid_domain_format(self, domain: str) -> bool:
        """Validate domain format"""
        # Basic domain validation
        domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_regex.match(domain))
    
    def _clean_text_from_html(self, text: str) -> str:
        """Clean text from common HTML artifacts"""
        # Remove common HTML patterns that might confuse extraction
        patterns_to_clean = [
            # HTML tags and attributes
            r'<[^>]+>',  # Remove HTML tags
            r'href\s*=\s*["\'][^"\']*["\']',  # Remove href attributes
            r'src\s*=\s*["\'][^"\']*["\']',   # Remove src attributes
            
            # Broken HTML entities
            r'&[a-zA-Z]+;',  # HTML entities like &nbsp;
            r'&#\d+;',       # Numeric HTML entities
            
            # Common markdown/HTML artifacts
            r'\[SS\d+\.\d+\]',  # [SS9.1] type artifacts
            r'</a>',            # Closing anchor tags
            r'">.*?</a>',       # Anchor tag content
        ]
        
        cleaned_text = text
        for pattern in patterns_to_clean:
            cleaned_text = re.sub(pattern, ' ', cleaned_text, flags=re.IGNORECASE)
        
        # Clean up extra whitespace
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
        
        return cleaned_text.strip()
    
    def _normalize_defanged_text(self, text: str) -> str:
        """Convert defanged indicators to normal format for extraction"""
        # Replace [.] with .
        text = re.sub(r'\[\.?\]', '.', text)
        # Replace [dot] with .
        text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
        # Replace (.) with .
        text = re.sub(r'\(\.?\)', '.', text)
        # Replace {.} with .
        text = re.sub(r'\{\.?\}', '.', text)
        # Replace [:]/:[] with :
        text = re.sub(r'\[:\]|:\[\]', ':', text)
        # Replace hxxp/hXXp with http
        text = re.sub(r'hxxps?', 'https', text, flags=re.IGNORECASE)
        # Replace [://] with ://
        text = re.sub(r'\[://\]', '://', text)
        return text
    
    def _extract_known_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract entities that match our predefined lists"""
        entities = defaultdict(set)
        
        if not self.known_entities:
            return {}
        
        # Convert text to lowercase for matching
        text_lower = text.lower()
        
        # Entity types to check - MUST MATCH ALL PREDEFINED TYPES IN DATABASE
        entity_types_to_check = [
            'apt_group',         # APT groups from MISP
            'ransomware_group',  # Ransomware groups from RansomLook  
            'malware_family',    # Malware families from MISP
            'company',           # Companies from SQL file
            'industry',          # Industries from SQL file
            'attack_type',       # Attack types from SQL file
            'platform'           # Platforms (OS, software) from SQL file
        ]
        
        for entity_type in entity_types_to_check:
            if entity_type not in self.known_entities:
                continue
                
            for known_value in self.known_entities[entity_type]:
                # Create word boundary pattern for exact matching
                # This prevents matching "Apple" in "Appleton" or "Pineapple"
                pattern = r'\b' + re.escape(known_value) + r'\b'
                
                if re.search(pattern, text_lower, re.IGNORECASE):
                    # Find the original case version in the text
                    original_case_match = re.search(pattern, text, re.IGNORECASE)
                    if original_case_match:
                        original_value = original_case_match.group()
                        entities[entity_type].add(original_value)
                    else:
                        # Fallback to the known value with proper case
                        # Look up the original case from the database
                        for orig_key, values in self.known_entities.items():
                            if orig_key == entity_type and known_value in values:
                                # Try to find the original case
                                try:
                                    result = self.session.execute(text("""
                                        SELECT value FROM cluster.entities 
                                        WHERE entity_type = :type 
                                        AND normalized_value = :normalized
                                        AND is_predefined = TRUE
                                        LIMIT 1
                                    """), {
                                        'type': entity_type,
                                        'normalized': known_value
                                    })
                                    row = result.first()
                                    if row:
                                        entities[entity_type].add(row.value)
                                    else:
                                        entities[entity_type].add(known_value.title())
                                except:
                                    entities[entity_type].add(known_value.title())
                                break
        
        # Convert sets to lists
        return {k: list(v) for k, v in entities.items() if v}
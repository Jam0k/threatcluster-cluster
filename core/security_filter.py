#!/usr/bin/env python3
"""
Security Article Filter
Determines if articles are cybersecurity-related
"""

import re
from typing import Tuple, Set
import yaml
import os


class SecurityFilter:
    """Filter articles to only include cybersecurity content"""
    
    def __init__(self, config_path: str = None):
        """Initialize with configuration"""
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.config = config.get('security_filtering', {})
        self.min_score = self.config.get('min_security_score', 0.3)
        
        # Load keywords from configuration or use defaults
        self._load_keywords()
        self._compile_patterns()
    
    def _load_keywords(self):
        """Load security keywords - could be extended to load from config"""
        # Core security keywords that MUST appear
        self.required_keywords = {
            # Attacks and incidents
            'breach', 'breached', 'hack', 'hacked', 'hacking', 'cyberattack', 'cyber-attack',
            'cyber attack', 'security incident', 'data breach', 'network breach', 'system breach',
            'compromise', 'compromised', 'infiltration', 'intrusion', 'unauthorized access',
            'attack campaign', 'targeted attack', 'supply chain attack', 'insider threat',
            
            # Ransomware and malware
            'ransomware', 'malware', 'trojan', 'virus', 'worm', 'backdoor', 'rootkit',
            'spyware', 'adware', 'keylogger', 'stealer', 'banking trojan', 'infostealer',
            'rat', 'remote access trojan', 'botnet', 'cryptominer', 'fileless malware',
            
            # Phishing and social engineering
            'phishing', 'spear-phishing', 'whaling', 'smishing', 'vishing', 
            'business email compromise', 'bec', 'email spoofing', 'typosquatting',
            'watering hole', 'social engineering',
            
            # Vulnerabilities and exploits
            'exploit', 'exploited', 'exploitation', 'zero-day', '0-day', 'vulnerability',
            'vulnerabilities', 'cve-', 'security flaw', 'security issue', 
            'buffer overflow', 'code injection', 'rce', 'remote code execution',
            'sql injection', 'xss', 'cross-site scripting', 'csrf',
            
            # DDoS and network attacks
            'ddos', 'distributed denial of service', 'dos', 'denial of service',
            'amplification attack', 'reflection attack', 'volumetric attack',
            
            # Threat actors
            'apt', 'threat actor', 'threat group', 'hacker', 'hackers', 'attacker',
            'cybercriminal', 'threat campaign',
            
            # Data and financial crimes
            'data leak', 'data theft', 'data exfiltration', 'data exposure',
            'pii exposed', 'personal data', 'sensitive data', 'credentials stolen',
            'fraud', 'identity theft', 'credit card theft', 'payment card',
            
            # Security measures
            'patch', 'patched', 'security update', 'security advisory', 'security bulletin',
            'hotfix', 'emergency patch', 'vulnerability disclosure', 'bug bounty',
            
            # Compliance
            'gdpr breach', 'hipaa breach', 'compliance violation', 'regulatory fine',
            'privacy breach',
            
            # Cloud and IoT
            'cloud breach', 's3 bucket exposed', 'cloud misconfiguration', 'container escape',
            'iot vulnerability', 'iot botnet', 'firmware vulnerability',
            
            # Cryptocurrency
            'crypto theft', 'cryptocurrency hack', 'defi hack', 'smart contract vulnerability',
            'blockchain attack', 'ransomware payment',
            
            # General security terms (added to be less restrictive)
            'cybersecurity', 'cyber security', 'infosec', 'information security',
            'security research', 'threat research', 'threat intelligence', 'threat report',
            'security tool', 'security solution', 'security platform', 'security software',
            'security risk', 'security threat', 'security vulnerability', 'security incident',
            'authentication', 'authorization', 'encryption', 'cryptography',
            'firewall', 'antivirus', 'endpoint protection', 'edr', 'xdr', 'siem',
            'penetration test', 'pentest', 'red team', 'blue team', 'purple team',
            'security audit', 'security assessment', 'risk assessment',
            'threat detection', 'threat hunting', 'incident response', 'forensics',
            'security operations', 'soc', 'security monitoring',
            'cyber defense', 'cyber warfare', 'cyber espionage',
            'security researcher', 'bug hunter', 'white hat', 'black hat',
            'security conference', 'def con', 'black hat', 'rsa conference',
            'cisa', 'nsa', 'fbi', 'cert', 'csirt',
            
            # Privacy and data protection (broader tech coverage)
            'privacy', 'data privacy', 'user privacy', 'privacy breach',
            'data protection', 'gdpr', 'ccpa', 'privacy policy',
            'surveillance', 'tracking', 'data collection', 'privacy concern',
            
            # Tech security topics
            'password', 'two-factor', '2fa', 'mfa', 'multi-factor',
            'security feature', 'secure', 'security fix', 'security improvement',
            'vpn', 'tor', 'proxy', 'anonymity', 'privacy tool',
            'secure messaging', 'end-to-end encryption', 'signal', 'whatsapp security',
            
            # Broader attack terms
            'attack', 'attacks', 'attacked', 'targeting', 'targets',
            'victim', 'victims', 'affected', 'impacted', 'exposed',
            'leaked', 'leak', 'stolen', 'theft', 'compromise',
            
            # Company/service + security context
            'google security', 'microsoft security', 'apple security',
            'facebook security', 'twitter security', 'instagram security',
            'whatsapp security', 'telegram security', 'discord security',
            
            # Security warnings and alerts
            'warning', 'alert', 'advisory', 'bulletin', 'notification',
            'urgent', 'critical', 'high risk', 'dangerous', 'malicious',
            
            # Scams and fraud (common in general news)
            'scam', 'scammer', 'phish', 'fraudulent', 'fake',
            'impersonation', 'spoofing', 'deception', 'con artist'
        }
        
        # High-confidence patterns
        self.high_confidence_terms = {
            'cve-', 'ransomware', 'malware', 'breach', 'hacked', 'vulnerability', 
            'exploit', 'zero-day', 'apt', 'cybersecurity', 'cyber security', 'infosec',
            'threat intelligence', 'security research', 'incident response'
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        # Keyword pattern
        self.keyword_pattern = re.compile(
            r'\b(?:' + '|'.join(re.escape(k) for k in self.required_keywords) + r')\b',
            re.IGNORECASE
        )
        
        # High confidence patterns
        self.high_confidence_patterns = [
            re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE),
            re.compile(r'\b(?:' + '|'.join(self.high_confidence_terms) + r')\b', re.IGNORECASE),
            re.compile(r'\bAPT\s*\d+\b', re.IGNORECASE)
        ]
        
        # Exclusion patterns - only very specific non-security content
        self.exclusion_patterns = [
            # Only exclude if it's PURELY about these topics with NO security context
            re.compile(r'^(?!.*(?:cyber|security|hack|breach|privacy|data|password|scam|fraud|leak|attack|threat)).*\b(?:recipe|cooking|baking)\b', re.IGNORECASE),
            re.compile(r'^(?!.*(?:cyber|security|hack|breach|privacy|data)).*\b(?:fashion show|runway|designer clothing)\b', re.IGNORECASE),
            re.compile(r'^(?!.*(?:cyber|security|hack|breach|fraud)).*\b(?:lottery winner|powerball|megamillions)\b', re.IGNORECASE),
            
            # Very specific patterns that are never security-related
            re.compile(r'\b(?:horoscope|astrology|zodiac)\b', re.IGNORECASE),
            re.compile(r'\b(?:celebrity gossip|red carpet|dating rumors)\b', re.IGNORECASE)
        ]
    
    def is_security_article(self, article: dict) -> Tuple[bool, float, str]:
        """
        Determine if article is security-related
        
        Args:
            article: Dict with 'title' and 'content' keys
            
        Returns:
            (is_security, confidence_score, reason)
        """
        title = article.get('title', '').lower()
        content = article.get('content', '').lower()
        full_text = f"{title} {content}"
        
        # Early exit for exclusions
        for pattern in self.exclusion_patterns:
            if pattern.search(full_text):
                return False, 0.0, "Matches exclusion pattern"
        
        # Quick high-confidence check
        for pattern in self.high_confidence_patterns:
            if pattern.search(full_text):
                return True, 0.9, "High-confidence security pattern"
        
        # Find keyword matches
        keyword_matches = set(self.keyword_pattern.findall(full_text))
        
        if not keyword_matches:
            return False, 0.0, "No security keywords found"
        
        # Calculate confidence score
        score = 0.0
        reasons = []
        
        # Keyword scoring - more generous
        keyword_count = len(keyword_matches)
        if keyword_count >= 3:
            keyword_score = 0.5
        elif keyword_count >= 2:
            keyword_score = 0.3
        elif keyword_count >= 1:
            keyword_score = 0.2
        else:
            keyword_score = 0
        
        score += keyword_score
        reasons.append(f"{keyword_count} security keywords")
        
        # Title emphasis
        title_keywords = sum(1 for k in keyword_matches if k in title)
        if title_keywords > 0:
            score += 0.2
            reasons.append("Security terms in title")
        
        # Context analysis
        if any(term in full_text for term in ['actively exploited', 'in the wild', 'emergency']):
            score += 0.2
            reasons.append("Urgent security context")
        
        # Source-based scoring - bonus for known security sources
        source = article.get('source', '').lower()
        security_sources = {
            'crowdstrike', 'mandiant', 'fireeye', 'kaspersky', 'symantec',
            'mcafee', 'sophos', 'eset', 'malwarebytes', 'palo alto',
            'checkpoint', 'fortinet', 'rapid7', 'tenable', 'qualys',
            'recorded future', 'threatpost', 'bleepingcomputer', 'dark reading',
            'security week', 'the hacker news', 'krebs on security',
            'gb hackers', 'hackread', 'security online', 'cyware',
            'infosecurity', 'sc magazine', 'cso online', 'zero day',
            'threatconnect', 'crowdstrike blog', 'unit 42', 'talos',
            'securelist', 'welivesecurity', 'naked security', 'graham cluley',
            'schneier', 'sans', 'cert', 'cisa', 'us-cert', 'mitre'
        }
        
        if any(sec_source in source for sec_source in security_sources):
            score += 0.15
            reasons.append("Known security source")
        
        # Tech sites that often cover security - lower threshold
        tech_sources = {
            'wired', 'ars technica', 'engadget', 'the verge', 'techcrunch',
            'gizmodo', 'mashable', 'zdnet', 'cnet', 'pcmag',
            'guardian tech', 'ny times tech', 'bbc tech', 'sky news tech',
            'reuters tech', 'bloomberg tech', 'forbes tech', 'wsj tech',
            'vice', 'motherboard', 'hackernoon', 'slashdot'
        }
        
        if any(tech_source in source for tech_source in tech_sources) and keyword_matches:
            score += 0.1
            reasons.append("Tech source with security content")
        
        # Determine result
        is_security = score >= self.min_score
        reason = "; ".join(reasons) if reasons else "No clear security indicators"
        
        return is_security, score, reason
    
    def filter_articles(self, articles: list) -> Tuple[list, dict]:
        """
        Filter a list of articles
        
        Returns:
            (filtered_articles, statistics)
        """
        filtered = []
        stats = {
            'total': len(articles),
            'accepted': 0,
            'rejected': 0,
            'reasons': {}
        }
        
        for article in articles:
            is_security, score, reason = self.is_security_article(article)
            
            if is_security:
                article['security_score'] = score
                filtered.append(article)
                stats['accepted'] += 1
            else:
                stats['rejected'] += 1
                stats['reasons'][reason] = stats['reasons'].get(reason, 0) + 1
        
        return filtered, stats
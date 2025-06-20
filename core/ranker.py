#!/usr/bin/env python3
"""
Ranking Module
Unified ranking system for clusters and articles
"""

import json
import re
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
import logging
import yaml
import os

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class CyberSecurityRanker:
    """Unified ranking system for cybersecurity news feed"""
    
    def __init__(self, session: Session, config_path: str = None):
        self.session = session
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Entity weights
        self.entity_weights = self.config['entities']['weights']
        
        # Context-specific weights
        self.context_weights = {
            'company_as_victim': 100,
            'company_as_vendor': 25,
            'cve_exploited': 150,
            'cve_disclosed': 80,
        }
        
        # Critical keywords
        self.critical_keywords = {
            'zero-day': 150,
            '0-day': 150,
            'critical': 100,
            'emergency': 100,
            'urgent': 80,
            'actively exploited': 120,
            'in the wild': 100,
            'mass exploitation': 110,
            'ransomware': 90,
            'supply chain': 95,
            'backdoor': 85,
            'remote code execution': 90,
            'rce': 90,
            'privilege escalation': 70,
            'data breach': 80,
            'data leak': 75,
            'exfiltration': 85,
            'millions affected': 100,
            'widespread': 90,
            'global': 85,
            'critical infrastructure': 110,
            'healthcare': 95,
            'financial': 90,
            'government': 95,
            'nation-state': 100,
            'apt': 95,
            'patch now': 100,
            'update immediately': 95,
            'advisory': 70,
            'disclosure': 75
        }
        
        # Source credibility
        self.source_credibility = self.config['source_credibility']
        
        # Critical sectors
        self.critical_sectors = {
            'healthcare', 'health', 'hospital', 'medical',
            'energy', 'power', 'electricity', 'nuclear', 'grid',
            'water', 'wastewater', 'dam',
            'transportation', 'aviation', 'rail', 'maritime',
            'financial', 'banking', 'finance', 'payment',
            'government', 'federal', 'military', 'defense',
            'communications', 'telecom', 'internet',
            'manufacturing', 'chemical', 'industrial',
            'food', 'agriculture',
            'emergency', 'critical'
        }
        
        # Load threat actor scores
        self._threat_actor_scores = {}
        self._load_threat_actor_scores()
    
    def _load_threat_actor_scores(self):
        """Load threat actor scores from database"""
        try:
            result = self.session.execute(text("""
                SELECT LOWER(value) as name, entity_type, occurrence_count
                FROM cluster.entities
                WHERE entity_type IN ('apt_group', 'ransomware_group', 'malware_family')
                AND (is_predefined = TRUE OR occurrence_count > 10)
                ORDER BY occurrence_count DESC
            """))
            
            for row in result:
                base_score = {
                    'apt_group': 95,
                    'ransomware_group': 90,
                    'malware_family': 80
                }.get(row.entity_type, 70)
                
                if row.occurrence_count > 100:
                    score = base_score + 10
                elif row.occurrence_count > 50:
                    score = base_score + 5
                else:
                    score = base_score
                
                self._threat_actor_scores[row.name] = min(score, 120)
                
        except Exception as e:
            logger.warning(f"Could not load threat actor scores: {e}")
    
    def update_rankings(self) -> Dict:
        """Update all rankings"""
        clusters_ranked = self._rank_clusters()
        articles_ranked = self._rank_articles()
        
        logger.info(f"Ranked {clusters_ranked} clusters and {articles_ranked} articles")
        
        return {
            'clusters_ranked': clusters_ranked,
            'articles_ranked': articles_ranked,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    def _rank_clusters(self) -> int:
        """Rank all active clusters"""
        clusters = self.session.execute(text("""
            SELECT 
                c.id,
                c.created_at,
                c.updated_at,
                array_agg(DISTINCT a.id) as article_ids,
                array_agg(DISTINCT a.title) as titles,
                array_agg(DISTINCT a.source) as sources,
                array_agg(DISTINCT COALESCE(a.published_date, a.fetched_at)) as dates,
                COUNT(DISTINCT a.id) as article_count,
                COUNT(DISTINCT a.source) as source_count
            FROM cluster.clusters c
            JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
            JOIN cluster.articles a ON ca.article_id = a.id
            WHERE c.is_active = TRUE
            GROUP BY c.id
        """)).fetchall()
        
        for cluster in clusters:
            score = self._calculate_cluster_score(cluster)
            
            self.session.execute(text("""
                UPDATE cluster.clusters
                SET ranking_score = :score,
                    ranking_factors = :factors,
                    last_ranked_at = NOW()
                WHERE id = :cluster_id
            """), {
                'cluster_id': cluster.id,
                'score': score['total'],
                'factors': json.dumps(score['factors'])
            })
        
        self.session.commit()
        return len(clusters)
    
    def _calculate_cluster_score(self, cluster) -> Dict:
        """Calculate ranking score for a cluster"""
        factors = {}
        
        # Base score
        base_score = 100
        factors['base_cluster_bonus'] = 100
        
        # Source diversity
        source_score = min(cluster.source_count * 30, 120)
        factors['source_diversity'] = source_score
        
        # Size score
        size_score = min(cluster.article_count * 20, 100)
        factors['cluster_size'] = size_score
        
        # Recency
        latest_date = max(cluster.dates)
        recency_score = self._calculate_recency_score(latest_date)
        factors['recency'] = recency_score
        
        # Entity importance
        entity_score = self._calculate_cluster_entity_score(cluster.id)
        factors['entity_importance'] = entity_score
        
        # Keyword score
        keyword_score = 0
        critical_keywords_found = []
        
        for title in cluster.titles:
            if title:
                title_lower = title.lower()
                
                # Static keywords
                for keyword, weight in self.critical_keywords.items():
                    if keyword in title_lower:
                        keyword_score += weight
                        critical_keywords_found.append(keyword)
                
                # Dynamic threat actors
                for actor_name, score in self._threat_actor_scores.items():
                    if actor_name in title_lower:
                        keyword_score += score
                        critical_keywords_found.append(actor_name)
        
        keyword_score = min(keyword_score, 200)
        factors['critical_keywords'] = keyword_score
        factors['keywords_found'] = critical_keywords_found[:5]
        
        # Source credibility
        credibility_score = self._calculate_source_credibility(cluster.sources)
        factors['source_credibility'] = credibility_score
        
        # Velocity
        velocity_score = self._calculate_velocity_score(cluster)
        factors['velocity'] = velocity_score
        
        # Total score
        total_score = (
            base_score + source_score + size_score + recency_score +
            entity_score + keyword_score + credibility_score + velocity_score
        )
        
        # Apply multipliers
        multiplier = 1.0
        
        # Single source penalty
        if cluster.source_count == 1:
            multiplier *= 0.7
            factors['single_source_penalty'] = True
        
        # Critical infrastructure
        if self._targets_critical_infrastructure(cluster.id):
            multiplier *= 1.5
            factors['critical_infrastructure'] = True
        
        # Active exploitation
        if any('exploit' in str(title).lower() or 'in the wild' in str(title).lower() 
               for title in cluster.titles if title):
            multiplier *= 1.3
            factors['active_exploitation'] = True
        
        # Official source bonus
        has_official = any(
            source and any(official in source.lower() for official in ['cisa', 'cert', 'us-cert', 'nist'])
            for source in cluster.sources
        )
        if has_official:
            multiplier *= 1.2
            factors['official_source'] = True
        
        total_score *= multiplier
        
        return {
            'total': min(total_score, 2000),
            'factors': factors
        }
    
    def _calculate_recency_score(self, date) -> float:
        """Calculate recency score with exponential decay"""
        if not date:
            return 0
        
        if hasattr(date, 'tzinfo') and date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        hours_old = (now - date).total_seconds() / 3600
        
        if hours_old < 6:
            score = 150
        elif hours_old < 24:
            score = 150 * math.exp(-0.03 * hours_old)
        elif hours_old < 72:
            score = 150 * math.exp(-0.05 * hours_old)
        else:
            score = 150 * math.exp(-0.1 * hours_old)
        
        return max(score, 5)
    
    def _calculate_cluster_entity_score(self, cluster_id: int) -> float:
        """Calculate entity importance score for cluster"""
        entities = self.session.execute(text("""
            SELECT e.entity_type, e.value, cse.occurrence_count
            FROM cluster.cluster_shared_entities cse
            JOIN cluster.entities e ON cse.entity_id = e.id
            WHERE cse.cluster_id = :cluster_id
        """), {'cluster_id': cluster_id}).fetchall()
        
        titles = self.session.execute(text("""
            SELECT a.title
            FROM cluster.articles a
            JOIN cluster.cluster_articles ca ON a.id = ca.article_id
            WHERE ca.cluster_id = :cluster_id
        """), {'cluster_id': cluster_id}).fetchall()
        
        combined_titles = ' '.join(t.title.lower() for t in titles if t.title)
        
        score = 0
        
        for entity in entities:
            entity_weight = self.entity_weights.get(entity.entity_type, 20)
            
            # Context-aware scoring
            if entity.entity_type == 'company':
                victim_patterns = [
                    f"{entity.value.lower()} breach",
                    f"{entity.value.lower()} hacked",
                    f"{entity.value.lower()} ransomware",
                    f"{entity.value.lower()} attacked",
                ]
                if any(pattern in combined_titles for pattern in victim_patterns):
                    entity_weight = self.context_weights['company_as_victim']
                else:
                    entity_weight = self.context_weights['company_as_vendor']
            
            elif entity.entity_type == 'cve':
                if 'exploit' in combined_titles or 'in the wild' in combined_titles:
                    entity_weight = self.context_weights['cve_exploited']
                else:
                    cve_score = self._get_cve_severity_score(entity.value)
                    entity_weight = max(entity_weight, cve_score)
            
            weighted_score = entity_weight * (1 + (entity.occurrence_count - 1) * 0.2)
            score += weighted_score
        
        return min(score, 250)
    
    def _get_cve_severity_score(self, cve: str) -> float:
        """Estimate CVE severity score"""
        if not cve:
            return 50
        
        cve_lower = cve.lower()
        
        # Known critical CVEs
        critical_cves = {
            'cve-2021-44228': 150,  # Log4Shell
            'cve-2021-34527': 140,  # PrintNightmare
            'cve-2020-1472': 140,   # Zerologon
            'cve-2019-19781': 130,  # Citrix ADC
            'cve-2017-0144': 140,   # EternalBlue
        }
        
        if cve_lower in critical_cves:
            return critical_cves[cve_lower]
        
        # Year-based scoring
        year_match = re.search(r'cve-(\d{4})-', cve_lower)
        if year_match:
            year = int(year_match.group(1))
            current_year = datetime.now().year
            if year == current_year:
                return 100
            elif year == current_year - 1:
                return 80
            else:
                return 60
        
        return 70
    
    def _calculate_source_credibility(self, sources: List[str]) -> float:
        """Calculate credibility score based on sources"""
        if not sources:
            return 0
        
        total_credibility = 0
        source_count = 0
        
        for source in sources:
            if source:
                source_lower = source.lower()
                credibility = self.source_credibility.get('default', 0.8)
                
                for pattern, cred_score in self.source_credibility.items():
                    if pattern in source_lower:
                        credibility = max(credibility, cred_score)
                
                total_credibility += credibility
                source_count += 1
        
        if source_count == 0:
            return 0
        
        avg_credibility = total_credibility / source_count
        diversity_bonus = min(source_count * 10, 50)
        
        return (avg_credibility * 50) + diversity_bonus
    
    def _calculate_velocity_score(self, cluster) -> float:
        """Calculate cluster velocity score"""
        if not cluster.dates:
            return 0
        
        oldest = min(cluster.dates)
        newest = max(cluster.dates)
        
        if hasattr(oldest, 'tzinfo') and oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        if hasattr(newest, 'tzinfo') and newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)
        
        time_span_hours = (newest - oldest).total_seconds() / 3600
        
        if time_span_hours < 1:
            return 50  # Breaking news
        elif time_span_hours < 6:
            return 30  # Rapid development
        elif time_span_hours < 24:
            return 20  # Same day
        else:
            return 10
    
    def _targets_critical_infrastructure(self, cluster_id: int) -> bool:
        """Check if cluster targets critical infrastructure"""
        victims = self.session.execute(text("""
            SELECT e.value
            FROM cluster.cluster_shared_entities cse
            JOIN cluster.entities e ON cse.entity_id = e.id
            WHERE cse.cluster_id = :cluster_id
            AND e.entity_type IN ('other', 'company')
        """), {'cluster_id': cluster_id}).fetchall()
        
        for victim in victims:
            if victim.value:
                victim_lower = victim.value.lower()
                for sector in self.critical_sectors:
                    if sector in victim_lower:
                        return True
        
        return False
    
    def _rank_articles(self) -> int:
        """Rank unclustered articles"""
        articles = self.session.execute(text("""
            SELECT 
                a.id,
                a.title,
                a.source,
                COALESCE(a.published_date, a.fetched_at) as article_date,
                a.metadata
            FROM cluster.articles a
            WHERE NOT EXISTS (
                SELECT 1 FROM cluster.cluster_articles ca
                JOIN cluster.clusters c ON ca.cluster_id = c.id
                WHERE ca.article_id = a.id AND c.is_active = TRUE
            )
            AND a.processed_at IS NOT NULL
            AND COALESCE(a.published_date, a.fetched_at) > NOW() - INTERVAL '30 days'
        """)).fetchall()
        
        for article in articles:
            score = self._calculate_article_score(article)
            
            metadata = article.metadata or {}
            metadata['ranking_score'] = str(score['total'])
            metadata['ranking_factors'] = score['factors']
            metadata['last_ranked'] = datetime.now(timezone.utc).isoformat()
            
            self.session.execute(text("""
                UPDATE cluster.articles
                SET metadata = :metadata
                WHERE id = :article_id
            """), {
                'article_id': article.id,
                'metadata': json.dumps(metadata)
            })
        
        self.session.commit()
        return len(articles)
    
    def _calculate_article_score(self, article) -> Dict:
        """Calculate ranking score for article"""
        factors = {}
        
        # Base score
        base_score = 100
        factors['base_article'] = 100
        
        # Recency
        recency_score = self._calculate_recency_score(article.article_date)
        factors['recency'] = recency_score
        
        # Entity importance
        entity_score = self._calculate_article_entity_score(article.id)
        factors['entity_importance'] = entity_score
        
        # Keywords
        keyword_score = 0
        critical_keywords_found = []
        
        if article.title:
            title_lower = article.title.lower()
            
            for keyword, weight in self.critical_keywords.items():
                if keyword in title_lower:
                    keyword_score += weight
                    critical_keywords_found.append(keyword)
            
            for actor_name, score in self._threat_actor_scores.items():
                if actor_name in title_lower:
                    keyword_score += score
                    critical_keywords_found.append(actor_name)
        
        keyword_score = min(keyword_score, 200)
        factors['critical_keywords'] = keyword_score
        factors['keywords_found'] = critical_keywords_found[:3]
        
        # Source credibility
        credibility_score = 0
        if article.source:
            source_lower = article.source.lower()
            credibility = self.source_credibility.get('default', 0.8)
            
            for pattern, cred_score in self.source_credibility.items():
                if pattern in source_lower:
                    credibility = max(credibility, cred_score)
            
            credibility_score = credibility * 30
        
        factors['source_credibility'] = credibility_score
        
        # Total
        total_score = (
            base_score + recency_score + entity_score + 
            keyword_score + credibility_score
        )
        
        # Penalty for being unclustered
        total_score *= 0.7
        
        return {
            'total': min(total_score, 800),
            'factors': factors
        }
    
    def _calculate_article_entity_score(self, article_id: int) -> float:
        """Calculate entity score for article"""
        article_info = self.session.execute(text("""
            SELECT title
            FROM cluster.articles
            WHERE id = :article_id
        """), {'article_id': article_id}).fetchone()
        
        title_lower = article_info.title.lower() if article_info and article_info.title else ""
        
        entities = self.session.execute(text("""
            SELECT e.entity_type, e.value
            FROM cluster.article_entities ae
            JOIN cluster.entities e ON ae.entity_id = e.id
            WHERE ae.article_id = :article_id
        """), {'article_id': article_id}).fetchall()
        
        score = 0
        
        for entity in entities:
            entity_weight = self.entity_weights.get(entity.entity_type, 20)
            
            # Context-aware scoring
            if entity.entity_type == 'company':
                victim_patterns = [
                    f"{entity.value.lower()} breach",
                    f"{entity.value.lower()} hacked",
                    f"{entity.value.lower()} ransomware",
                ]
                if any(pattern in title_lower for pattern in victim_patterns):
                    entity_weight = self.context_weights['company_as_victim']
                else:
                    entity_weight = self.context_weights['company_as_vendor']
            
            elif entity.entity_type == 'cve':
                if 'exploit' in title_lower or 'in the wild' in title_lower:
                    entity_weight = self.context_weights['cve_exploited']
                else:
                    cve_score = self._get_cve_severity_score(entity.value)
                    entity_weight = max(entity_weight, cve_score)
            
            score += entity_weight
        
        return min(score, 300)
"""
Pure Semantic Clustering Module
Replaces the old event_clusterer with modern semantic clustering approach.
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
import hashlib
import re
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN, AgglomerativeClustering
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer

from cluster.core.entity_extractor import EntityExtractor
from cluster.core.entity_validator import EntityValidator

logger = logging.getLogger(__name__)


class ContentPreprocessor:
    """Preprocess and clean article content for better semantic analysis"""
    
    def __init__(self):
        # Common noise patterns in security articles
        self.noise_patterns = [
            r'(?:Subscribe|Sign up|Newsletter|Advertisement)',
            r'(?:Read more|Continue reading|Click here)',
            r'(?:Share|Tweet|Facebook|LinkedIn|Email)',
            r'The post .* appeared first on',
            r'Source: .*$',
            r'https?://\S+',
            r'\[.*?\]',  # Remove markdown links
            r'<!--.*?-->',  # Remove HTML comments
        ]
        
        # Security-specific stop words to reduce noise
        self.security_stop_words = {
            'security', 'cybersecurity', 'cyber', 'threat', 'attack', 'vulnerability',
            'update', 'patch', 'advisory', 'disclosure', 'report', 'article',
            'news', 'blog', 'post', 'read', 'more', 'click', 'here'
        }
    
    def clean_text(self, text: str) -> str:
        """Clean text for better semantic analysis"""
        if not text:
            return ""
        
        # Remove noise patterns
        for pattern in self.noise_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        # Truncate very long content
        if len(text) > 5000:
            text = text[:5000]
        
        return text.strip()
    
    def prepare_for_embedding(self, title: str, content: str) -> str:
        """Prepare text for embedding generation"""
        # Clean both
        title = self.clean_text(title)
        content = self.clean_text(content)
        
        # Weight title more heavily
        if content:
            # Use first 1000 chars of content
            content_preview = content[:1000]
            combined = f"{title}. {title}. {content_preview}"
        else:
            combined = title
        
        return combined


class SemanticClusterer:
    """Modern semantic clustering for cybersecurity articles"""
    
    def __init__(self, session: Session):
        self.session = session
        self.preprocessor = ContentPreprocessor()
        
        # Use better model for semantic similarity
        model_name = "sentence-transformers/all-mpnet-base-v2"
        logger.info(f"Loading embedding model: {model_name}")
        
        # Try to use cached model first to avoid rate limiting
        import os
        os.environ['HF_HUB_OFFLINE'] = '1'
        
        try:
            self.encoder = SentenceTransformer(model_name)
        except Exception as e:
            logger.warning(f"Failed to load model offline: {e}")
            # Try online if offline fails
            del os.environ['HF_HUB_OFFLINE']
            self.encoder = SentenceTransformer(model_name)
        
        # Clustering parameters
        self.min_cluster_size = 2
        self.max_cluster_size = 12  # Reduced from 20 to prevent over-clustering
        self.time_window_hours = 168  # 1 week
        self.min_similarity = 0.75  # Increased from 0.65 to require higher similarity
        self.min_coherence = 0.65  # Increased from 0.5 for tighter coherence
        
        # TF-IDF for keyword extraction
        self.tfidf = TfidfVectorizer(
            max_features=1000,
            min_df=2,
            max_df=0.8,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        # Entity extractor for post-processing
        self.entity_extractor = EntityExtractor(session)
        self.entity_validator = EntityValidator(session)
        
        # Deduplication parameters
        self.cluster_similarity_threshold = 0.75  # Increased from 0.65 for stricter deduplication
        self.min_shared_entities = 2  # Minimum shared entities to consider clusters similar
        self.title_similarity_threshold = 0.8  # High threshold for title similarity to catch near-duplicates
    
    def cluster_articles(self, days_back: int = 7) -> Dict[str, int]:
        """Main clustering method"""
        # Limit days_back to prevent overflow
        if days_back > 3650:  # 10 years max
            days_back = 3650
            
        logger.info(f"Starting semantic clustering for articles from last {days_back} days")
        
        # Fetch recent articles, excluding those already in active clusters
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        result = self.session.execute(text("""
            SELECT a.id, a.url, a.title, a.content, a.full_content, a.source, a.published_date
            FROM cluster.articles a
            LEFT JOIN cluster.cluster_articles ca ON a.id = ca.article_id
            LEFT JOIN cluster.clusters c ON ca.cluster_id = c.id AND c.is_active = true
            WHERE a.published_date >= :cutoff_date
            AND a.title IS NOT NULL
            AND a.title != ''
            AND c.id IS NULL  -- Only articles not in active clusters
            ORDER BY a.published_date DESC
        """), {'cutoff_date': cutoff_date})
        
        articles = []
        seen_titles = set()  # Track titles to avoid duplicate articles with same title
        
        for row in result:
            # Additional check: skip duplicate titles (normalized)
            normalized_title = self.preprocessor.clean_text(row.title).lower()
            if normalized_title in seen_titles:
                logger.debug(f"Skipping duplicate title: {row.title}")
                continue
            seen_titles.add(normalized_title)
                
            article = {
                'id': row.id,
                'url': row.url,
                'title': row.title,
                'content': row.content or row.full_content or '',
                'source': row.source,
                'published_date': row.published_date
            }
            articles.append(article)
        
        if not articles:
            logger.warning("No articles found for clustering")
            return {'clusters_created': 0, 'articles_clustered': 0}
        
        logger.info(f"Found {len(articles)} articles to cluster (after filtering already-clustered)")
        
        # Get existing active clusters for deduplication comparison (extended window)
        existing_clusters = self._get_existing_active_clusters(days_back * 2)  # Look back twice as far
        logger.info(f"Found {len(existing_clusters)} existing active clusters for comparison")
        
        # Generate embeddings
        embeddings = self._generate_embeddings(articles)
        
        # Perform clustering
        clusters = self._cluster_by_similarity(embeddings, articles)
        
        # Filter out clusters similar to existing ones
        clusters = self._filter_duplicate_clusters(clusters, existing_clusters)
        
        # Post-process: Extract entities for display
        self._extract_entities_for_clusters(clusters)
        
        # Save clusters to database
        results = self._save_clusters(clusters)
        
        return results
    
    def _generate_embeddings(self, articles: List[Dict]) -> np.ndarray:
        """Generate embeddings for all articles"""
        texts = []
        for article in articles:
            combined_text = self.preprocessor.prepare_for_embedding(
                article['title'], article['content']
            )
            texts.append(combined_text)
        
        logger.info("Generating embeddings...")
        embeddings = self.encoder.encode(texts, show_progress_bar=True)
        
        return embeddings
    
    def _cluster_by_similarity(self, embeddings: np.ndarray, articles: List[Dict]) -> List[Dict]:
        """Cluster articles using DBSCAN or hierarchical clustering"""
        # Calculate similarity matrix
        similarity_matrix = cosine_similarity(embeddings)
        
        # Convert to distance matrix (ensure non-negative)
        distance_matrix = np.maximum(0, 1 - similarity_matrix)
        
        # Try DBSCAN first
        logger.info(f"Clustering with DBSCAN (min_similarity={self.min_similarity})...")
        clustering = DBSCAN(
            eps=1 - self.min_similarity,  # eps=0.25 with min_similarity=0.75
            min_samples=self.min_cluster_size,
            metric='precomputed'
        )
        
        labels = clustering.fit_predict(distance_matrix)
        
        # Group articles by cluster
        cluster_groups = defaultdict(list)
        for article, label in zip(articles, labels):
            if label != -1:  # Ignore noise points
                cluster_groups[label].append(article)
        
        # If too few clusters, try hierarchical
        if len(cluster_groups) < 3:
            logger.info(f"Trying hierarchical clustering (min_similarity={self.min_similarity})...")
            clustering = AgglomerativeClustering(
                n_clusters=None,
                distance_threshold=1 - self.min_similarity,  # distance_threshold=0.25 with min_similarity=0.75
                metric='precomputed',
                linkage='average'
            )
            
            labels = clustering.fit_predict(distance_matrix)
            
            cluster_groups = defaultdict(list)
            for article, label in zip(articles, labels):
                cluster_groups[label].append(article)
        
        # Create cluster objects
        clusters = []
        rejected_size = 0
        rejected_time = 0
        rejected_coherence = 0
        
        for label, cluster_articles in cluster_groups.items():
            if self.min_cluster_size <= len(cluster_articles) <= self.max_cluster_size:
                # Check time constraint
                times = [a['published_date'] for a in cluster_articles]
                time_span = (max(times) - min(times)).total_seconds() / 3600
                
                if time_span <= self.time_window_hours:
                    # Calculate coherence
                    article_indices = [articles.index(a) for a in cluster_articles]
                    cluster_embeddings = embeddings[article_indices]
                    coherence = self._calculate_coherence(cluster_embeddings)
                    
                    if coherence >= self.min_coherence:
                        clusters.append({
                            'articles': cluster_articles,
                            'coherence': coherence,
                            'time_span': time_span,
                            'embeddings': cluster_embeddings
                        })
                    else:
                        rejected_coherence += 1
                        logger.debug(f"Rejected cluster with {len(cluster_articles)} articles due to low coherence: {coherence:.3f}")
                else:
                    rejected_time += 1
                    logger.debug(f"Rejected cluster with {len(cluster_articles)} articles due to time span: {time_span:.1f} hours")
            else:
                rejected_size += 1
                if len(cluster_articles) > self.max_cluster_size:
                    logger.warning(f"Rejected cluster with {len(cluster_articles)} articles (exceeds max size of {self.max_cluster_size})")
        
        # Sort by coherence
        clusters.sort(key=lambda x: x['coherence'], reverse=True)
        
        logger.info(f"Created {len(clusters)} clusters")
        if rejected_size + rejected_time + rejected_coherence > 0:
            logger.info(f"Rejected clusters: {rejected_size} (size), {rejected_time} (time), {rejected_coherence} (coherence)")
        
        return clusters
    
    def _calculate_coherence(self, embeddings: np.ndarray) -> float:
        """Calculate cluster coherence score"""
        if len(embeddings) < 2:
            return 1.0
        
        # Calculate pairwise similarities
        similarities = cosine_similarity(embeddings)
        
        # Get average similarity (excluding diagonal)
        n = len(embeddings)
        total_sim = (similarities.sum() - n) / (n * (n - 1))
        
        return float(total_sim)
    
    def _extract_keywords(self, articles: List[Dict], top_n: int = 5) -> List[str]:
        """Extract keywords from a cluster of articles"""
        if not articles:
            return []
        
        # Combine all text
        texts = []
        for article in articles:
            text = self.preprocessor.clean_text(
                f"{article['title']} {article.get('content') or article.get('full_content') or ''}"
            )
            texts.append(text)
        
        try:
            # Fit TF-IDF on cluster texts
            tfidf_matrix = self.tfidf.fit_transform(texts)
            
            # Get feature names
            feature_names = self.tfidf.get_feature_names_out()
            
            # Sum TF-IDF scores across documents
            scores = tfidf_matrix.sum(axis=0).A1
            
            # Get top keywords
            top_indices = scores.argsort()[-top_n:][::-1]
            keywords = [feature_names[i] for i in top_indices]
            
            return keywords
        except:
            return []
    
    def _extract_entities_for_clusters(self, clusters: List[Dict]):
        """Post-process: Extract entities for display purposes only"""
        logger.info("Extracting entities for cluster display...")
        
        for cluster in clusters:
            cluster_entities = defaultdict(set)
            
            for article in cluster['articles']:
                # Get entities from database
                result = self.session.execute(text("""
                    SELECT e.entity_type, e.value
                    FROM cluster.entities e
                    JOIN cluster.article_entities ae ON e.id = ae.entity_id
                    WHERE ae.article_id = :article_id
                    AND ae.confidence >= 0.7
                """), {'article_id': article['id']})
                
                for entity_type, value in result:
                    cluster_entities[entity_type].add(value)
            
            # Store aggregated entities
            cluster['shared_entities'] = {k: list(v) for k, v in cluster_entities.items()}
            
            # Extract keywords
            cluster['keywords'] = self._extract_keywords(cluster['articles'])
    
    def _save_clusters(self, clusters: List[Dict]) -> Dict[str, int]:
        """Save clusters to database"""
        clusters_created = 0
        articles_clustered = 0
        
        for cluster_data in clusters:
            try:
                # Create cluster - Generate deterministic UUID from article content (without timestamp)
                # This ensures consistent UUIDs for similar clusters
                article_titles = sorted([self.preprocessor.clean_text(a['title']).lower() for a in cluster_data['articles']])
                article_sources = sorted([a['source'] for a in cluster_data['articles']])
                
                # Use normalized content-based hash without timestamp or article IDs for deduplication
                uuid_source = f"{'|'.join(article_titles)}_{'-'.join(article_sources)}"
                base_cluster_uuid = hashlib.md5(uuid_source.encode()).hexdigest()[:8]
                cluster_uuid = base_cluster_uuid
                
                # Try to insert, and if duplicate, add random suffix
                max_retries = 5
                for retry in range(max_retries):
                    try:
                        result = self.session.execute(text("""
                            INSERT INTO cluster.clusters 
                            (cluster_uuid, cluster_type, is_active, created_at, ranking_score)
                            VALUES (:cluster_uuid, :cluster_type, :is_active, :created_at, :ranking_score)
                            RETURNING id
                        """), {
                            'cluster_uuid': cluster_uuid,
                            'cluster_type': 'semantic',
                            'is_active': True,
                            'created_at': datetime.utcnow(),
                            'ranking_score': int(cluster_data['coherence'] * 100)
                        })
                        
                        cluster_id = result.scalar()
                        break  # Success, exit retry loop
                        
                    except Exception as e:
                        if "duplicate key value violates unique constraint" in str(e) and retry < max_retries - 1:
                            # Add random suffix to make UUID unique
                            cluster_uuid = f"{cluster_uuid[:6]}{uuid.uuid4().hex[:2]}"
                            self.session.rollback()  # Rollback the failed transaction
                            continue
                        else:
                            raise  # Re-raise if not a duplicate key error or max retries reached
                
                # Add articles to cluster
                for i, article in enumerate(cluster_data['articles']):
                    # Check if article is already in an active cluster
                    already_clustered = self.session.execute(text("""
                        SELECT c.id, c.cluster_uuid 
                        FROM cluster.cluster_articles ca
                        JOIN cluster.clusters c ON ca.cluster_id = c.id
                        WHERE ca.article_id = :article_id AND c.is_active = true
                        LIMIT 1
                    """), {
                        'article_id': article['id']
                    }).first()
                    
                    if already_clustered:
                        logger.warning(f"Article {article['id']} already in active cluster {already_clustered.id}, skipping")
                        continue
                    
                    self.session.execute(text("""
                        INSERT INTO cluster.cluster_articles
                        (cluster_id, article_id, is_primary, added_at)
                        VALUES (:cluster_id, :article_id, :is_primary, :added_at)
                    """), {
                        'cluster_id': cluster_id,
                        'article_id': article['id'],
                        'is_primary': i == 0,  # First article is primary
                        'added_at': datetime.utcnow()
                    })
                    articles_clustered += 1
                
                # Add shared entities
                for entity_type, values in cluster_data['shared_entities'].items():
                    for value in values[:10]:  # Limit to top 10 per type
                        # Find entity
                        result = self.session.execute(text("""
                            SELECT id FROM cluster.entities
                            WHERE value = :value AND entity_type = :entity_type
                            LIMIT 1
                        """), {
                            'value': value,
                            'entity_type': entity_type
                        })
                        
                        entity_id = result.scalar()
                        if entity_id:
                            self.session.execute(text("""
                                INSERT INTO cluster.cluster_shared_entities
                                (cluster_id, entity_id, occurrence_count)
                                VALUES (:cluster_id, :entity_id, 1)
                                ON CONFLICT (cluster_id, entity_id) DO NOTHING
                            """), {
                                'cluster_id': cluster_id,
                                'entity_id': entity_id
                            })
                
                clusters_created += 1
                
            except Exception as e:
                logger.error(f"Error saving cluster: {e}")
                self.session.rollback()
                continue
        
        self.session.commit()
        logger.info(f"Created {clusters_created} clusters with {articles_clustered} articles")
        
        return {
            'clusters_created': clusters_created,
            'articles_clustered': articles_clustered
        }
    
    def assign_to_existing_clusters(self, hours_back: int = 24) -> Dict[str, int]:
        """Assign new articles to existing clusters based on similarity"""
        cutoff_date = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Get unclustered articles
        result = self.session.execute(text("""
            SELECT a.id, a.url, a.title, a.content, a.full_content, a.source, a.published_date
            FROM cluster.articles a
            LEFT JOIN cluster.cluster_articles ca ON a.id = ca.article_id
            WHERE a.published_date >= :cutoff_date
            AND ca.article_id IS NULL
            AND a.title IS NOT NULL
            AND a.title != ''
            ORDER BY a.published_date DESC
        """), {'cutoff_date': cutoff_date})
        
        unclustered_articles = []
        for row in result:
            article = {
                'id': row.id,
                'url': row.url,
                'title': row.title,
                'content': row.content or row.full_content or '',
                'source': row.source,
                'published_date': row.published_date
            }
            unclustered_articles.append(article)
        
        if not unclustered_articles:
            return {'articles_assigned': 0}
        
        # Get recent active clusters
        result = self.session.execute(text("""
            SELECT id, cluster_uuid, created_at
            FROM cluster.clusters
            WHERE is_active = true
            AND created_at >= :cutoff_date
            ORDER BY created_at DESC
        """), {'cutoff_date': datetime.utcnow() - timedelta(days=7)})
        
        recent_clusters = []
        for row in result:
            recent_clusters.append({
                'id': row.id,
                'cluster_uuid': row.cluster_uuid,
                'created_at': row.created_at
            })
        
        if not recent_clusters:
            return {'articles_assigned': 0}
        
        articles_assigned = 0
        
        # Generate embeddings for unclustered articles
        unclustered_embeddings = self._generate_embeddings(unclustered_articles)
        
        for cluster in recent_clusters:
            # Get cluster articles
            result = self.session.execute(text("""
                SELECT a.id, a.url, a.title, a.content, a.full_content, a.source, a.published_date
                FROM cluster.articles a
                JOIN cluster.cluster_articles ca ON a.id = ca.article_id
                WHERE ca.cluster_id = :cluster_id
            """), {'cluster_id': cluster['id']})
            
            cluster_articles = []
            for row in result:
                article = {
                    'id': row.id,
                    'url': row.url,
                    'title': row.title,
                    'content': row.content or row.full_content or '',
                    'source': row.source,
                    'published_date': row.published_date
                }
                cluster_articles.append(article)
            
            if not cluster_articles:
                continue
            
            # Generate cluster centroid
            cluster_embeddings = self._generate_embeddings(cluster_articles)
            centroid = cluster_embeddings.mean(axis=0)
            
            # Check each unclustered article
            for i, article in enumerate(unclustered_articles):
                if article['id'] in [a['id'] for a in cluster_articles]:
                    continue
                
                # Calculate similarity to centroid
                similarity = cosine_similarity(
                    [unclustered_embeddings[i]], [centroid]
                )[0][0]
                
                if similarity >= self.min_similarity:
                    # Check time constraint
                    cluster_times = [a['published_date'] for a in cluster_articles]
                    time_diff = abs(
                        (article['published_date'] - max(cluster_times)).total_seconds() / 3600
                    )
                    
                    if time_diff <= 48:  # 48 hour window for existing clusters
                        # Add to cluster
                        self.session.execute(text("""
                            INSERT INTO cluster.cluster_articles
                            (cluster_id, article_id, is_primary, added_at)
                            VALUES (:cluster_id, :article_id, false, :added_at)
                            ON CONFLICT (cluster_id, article_id) DO NOTHING
                        """), {
                            'cluster_id': cluster['id'],
                            'article_id': article['id'],
                            'added_at': datetime.utcnow()
                        })
                        articles_assigned += 1
        
        self.session.commit()
        return {'articles_assigned': articles_assigned}
    
    def _get_existing_active_clusters(self, days_back: int = 7) -> List[Dict]:
        """Get existing active clusters for deduplication comparison"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        result = self.session.execute(text("""
            SELECT c.id, c.cluster_uuid, c.created_at, c.ranking_score,
                   array_agg(DISTINCT a.id) as article_ids,
                   array_agg(DISTINCT a.title) as article_titles,
                   array_agg(DISTINCT a.source) as sources
            FROM cluster.clusters c
            JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
            JOIN cluster.articles a ON ca.article_id = a.id
            WHERE c.is_active = true
            AND c.created_at >= :cutoff_date
            GROUP BY c.id, c.cluster_uuid, c.created_at, c.ranking_score
            ORDER BY c.created_at DESC
        """), {'cutoff_date': cutoff_date})
        
        clusters = []
        for row in result:
            # Get shared entities for this cluster
            entity_result = self.session.execute(text("""
                SELECT e.entity_type, e.value
                FROM cluster.entities e
                JOIN cluster.cluster_shared_entities cse ON e.id = cse.entity_id
                WHERE cse.cluster_id = :cluster_id
                AND e.entity_type != 'other'
            """), {'cluster_id': row.id})
            
            entities = {}
            for entity_type, value in entity_result:
                if entity_type not in entities:
                    entities[entity_type] = set()
                entities[entity_type].add(value)
            
            clusters.append({
                'id': row.id,
                'cluster_uuid': row.cluster_uuid,
                'created_at': row.created_at,
                'ranking_score': row.ranking_score,
                'article_ids': set(row.article_ids),
                'article_titles': list(row.article_titles),
                'sources': list(row.sources),
                'entities': entities
            })
        
        return clusters
    
    def _is_article_already_clustered(self, article_id: int) -> bool:
        """Check if an article is already part of an active cluster"""
        result = self.session.execute(text("""
            SELECT 1 FROM cluster.cluster_articles ca
            JOIN cluster.clusters c ON ca.cluster_id = c.id
            WHERE ca.article_id = :article_id
            AND c.is_active = true
            LIMIT 1
        """), {'article_id': article_id})
        
        return result.scalar() is not None
    
    def _calculate_cluster_similarity(self, cluster1_data: Dict, cluster2_data: Dict) -> float:
        """Calculate similarity between two clusters based on shared entities, titles, and article overlap"""
        similarity_scores = []
        
        # 1. Check for exact article overlap first (strongest signal)
        article_ids1 = set(cluster1_data.get('article_ids', []))
        article_ids2 = set(cluster2_data.get('article_ids', []))
        
        if article_ids1 and article_ids2:
            overlap_ratio = len(article_ids1 & article_ids2) / len(article_ids1 | article_ids2)
            if overlap_ratio > 0.3:  # If more than 30% article overlap, consider very similar
                return 0.9
        
        # 2. Entity similarity
        entity_similarity = self._calculate_entity_similarity(
            cluster1_data.get('entities', {}),
            cluster2_data.get('entities', {})
        )
        if entity_similarity > 0:
            similarity_scores.append(entity_similarity * 0.5)  # Weight entities heavily
        
        # 3. Title similarity (very important for duplicates)
        title_similarity = self._calculate_title_similarity(
            cluster1_data.get('article_titles', []),
            cluster2_data.get('article_titles', [])
        )
        if title_similarity > 0:
            similarity_scores.append(title_similarity * 0.5)  # Weight titles heavily
        
        # 4. Source similarity (same sources often indicate duplicate content)
        sources1 = set(cluster1_data.get('sources', []))
        sources2 = set(cluster2_data.get('sources', []))
        if sources1 and sources2:
            source_overlap = len(sources1 & sources2) / len(sources1 | sources2)
            if source_overlap > 0.5:  # High source overlap suggests duplication
                similarity_scores.append(0.3)
        
        # Return weighted average
        return sum(similarity_scores) if similarity_scores else 0.0
    
    def _calculate_entity_similarity(self, entities1: Dict, entities2: Dict) -> float:
        """Calculate similarity based on shared entities"""
        if not entities1 or not entities2:
            return 0.0
        
        all_types = set(entities1.keys()) | set(entities2.keys())
        if not all_types:
            return 0.0
        
        shared_count = 0
        total_count = 0
        
        for entity_type in all_types:
            set1 = entities1.get(entity_type, set())
            set2 = entities2.get(entity_type, set())
            
            if set1 and set2:
                # Calculate Jaccard similarity for this entity type
                intersection = len(set1 & set2)
                union = len(set1 | set2)
                if union > 0:
                    shared_count += intersection
                    total_count += union
        
        if total_count == 0:
            return 0.0
        
        return shared_count / total_count
    
    def _calculate_title_similarity(self, titles1: List[str], titles2: List[str]) -> float:
        """Calculate similarity based on article titles using both exact matching and TF-IDF"""
        if not titles1 or not titles2:
            return 0.0
        
        # First check for exact matches (after normalization)
        normalized_titles1 = set([self.preprocessor.clean_text(title).lower() for title in titles1])
        normalized_titles2 = set([self.preprocessor.clean_text(title).lower() for title in titles2])
        
        # If there are exact matches, return high similarity
        exact_matches = len(normalized_titles1 & normalized_titles2)
        total_unique = len(normalized_titles1 | normalized_titles2)
        
        if exact_matches > 0 and total_unique > 0:
            exact_similarity = exact_matches / total_unique
            if exact_similarity > 0.3:  # High threshold for exact matches
                return min(1.0, exact_similarity * 2)  # Boost exact matches
        
        try:
            # Fallback to TF-IDF similarity for semantic matching
            all_titles = [self.preprocessor.clean_text(title) for title in titles1 + titles2]
            all_titles = [title for title in all_titles if title]  # Remove empty strings
            
            if len(all_titles) < 2:
                return 0.0
            
            # Calculate TF-IDF similarity
            vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))
            tfidf_matrix = vectorizer.fit_transform(all_titles)
            
            # Split back into two groups
            group1_size = len(titles1)
            group1_vectors = tfidf_matrix[:group1_size]
            group2_vectors = tfidf_matrix[group1_size:]
            
            # Calculate average similarity between groups
            similarities = cosine_similarity(group1_vectors, group2_vectors)
            tfidf_similarity = float(similarities.mean())
            
            # Combine exact and TF-IDF similarities
            return max(exact_similarity, tfidf_similarity)
            
        except Exception as e:
            logger.warning(f"Error calculating title similarity: {e}")
            return exact_similarity if 'exact_similarity' in locals() else 0.0
    
    def _find_similar_existing_cluster(self, new_cluster_data: Dict, existing_clusters: List[Dict]) -> Optional[Dict]:
        """Find if there's an existing cluster similar to the new one"""
        for existing_cluster in existing_clusters:
            similarity = self._calculate_cluster_similarity(new_cluster_data, existing_cluster)
            
            if similarity >= self.cluster_similarity_threshold:
                logger.info(f"Found similar existing cluster {existing_cluster['cluster_uuid']} "
                           f"with similarity {similarity:.3f}")
                return existing_cluster
        
        return None
    
    def _filter_duplicate_clusters(self, new_clusters: List[Dict], existing_clusters: List[Dict]) -> List[Dict]:
        """Filter out clusters that are too similar to existing ones"""
        if not existing_clusters:
            return new_clusters
        
        filtered_clusters = []
        duplicates_found = 0
        
        for cluster in new_clusters:
            # Prepare cluster data for similarity comparison
            cluster_data = {
                'article_titles': [article['title'] for article in cluster['articles']],
                'article_ids': set([article['id'] for article in cluster['articles']]),
                'sources': [article['source'] for article in cluster['articles']],
                'entities': cluster.get('shared_entities', {})
            }
            
            # Check if this cluster is similar to any existing cluster
            similar_cluster = self._find_similar_existing_cluster(cluster_data, existing_clusters)
            
            if similar_cluster:
                duplicates_found += 1
                logger.info(f"Skipping duplicate cluster with {len(cluster['articles'])} articles "
                           f"(similar to existing cluster {similar_cluster['cluster_uuid']})")
                
                # Instead of creating a new cluster, assign articles to the existing one
                self._assign_articles_to_existing_cluster(cluster['articles'], similar_cluster['id'])
            else:
                filtered_clusters.append(cluster)
        
        logger.info(f"Filtered out {duplicates_found} duplicate clusters, "
                   f"keeping {len(filtered_clusters)} new clusters")
        
        return filtered_clusters
    
    def _assign_articles_to_existing_cluster(self, articles: List[Dict], cluster_id: int) -> None:
        """Assign articles to an existing cluster instead of creating a new one"""
        for article in articles:
            try:
                # First check if article is already in ANY active cluster
                already_clustered = self.session.execute(text("""
                    SELECT c.id, c.cluster_uuid 
                    FROM cluster.cluster_articles ca
                    JOIN cluster.clusters c ON ca.cluster_id = c.id
                    WHERE ca.article_id = :article_id AND c.is_active = true
                    LIMIT 1
                """), {
                    'article_id': article['id']
                }).first()
                
                if already_clustered:
                    logger.debug(f"Article {article['id']} already in active cluster {already_clustered.id}, skipping")
                    continue
                
                # Check if already assigned to this specific cluster to avoid duplicates
                existing = self.session.execute(text("""
                    SELECT 1 FROM cluster.cluster_articles
                    WHERE cluster_id = :cluster_id AND article_id = :article_id
                """), {
                    'cluster_id': cluster_id,
                    'article_id': article['id']
                }).scalar()
                
                if not existing:
                    self.session.execute(text("""
                        INSERT INTO cluster.cluster_articles
                        (cluster_id, article_id, is_primary, added_at)
                        VALUES (:cluster_id, :article_id, false, :added_at)
                    """), {
                        'cluster_id': cluster_id,
                        'article_id': article['id'],
                        'added_at': datetime.utcnow()
                    })
                    
                    logger.debug(f"Assigned article {article['id']} to existing cluster {cluster_id}")
                    
            except Exception as e:
                logger.error(f"Error assigning article {article['id']} to cluster {cluster_id}: {e}")
                continue
        
        # Commit the assignments
        try:
            self.session.commit()
        except Exception as e:
            logger.error(f"Error committing article assignments: {e}")
            self.session.rollback()
    
    def cleanup_duplicate_clusters(self, similarity_threshold: float = 0.8) -> Dict[str, int]:
        """Clean up duplicate clusters by merging very similar ones"""
        logger.info(f"Starting duplicate cluster cleanup with similarity threshold {similarity_threshold}")
        
        # Get all active clusters
        existing_clusters = self._get_existing_active_clusters(days_back=30)  # Look back 30 days
        
        if len(existing_clusters) < 2:
            return {'clusters_merged': 0, 'clusters_deactivated': 0}
        
        merged_count = 0
        deactivated_count = 0
        processed_clusters = set()
        
        for i, cluster1 in enumerate(existing_clusters):
            if cluster1['id'] in processed_clusters:
                continue
                
            # Find similar clusters
            similar_clusters = []
            for j, cluster2 in enumerate(existing_clusters[i+1:], i+1):
                if cluster2['id'] in processed_clusters:
                    continue
                    
                similarity = self._calculate_cluster_similarity(cluster1, cluster2)
                if similarity >= similarity_threshold:
                    similar_clusters.append((cluster2, similarity))
            
            if similar_clusters:
                # Sort by similarity (highest first)
                similar_clusters.sort(key=lambda x: x[1], reverse=True)
                
                # Keep the cluster with highest ranking score or newest
                clusters_to_compare = [cluster1] + [c[0] for c in similar_clusters]
                best_cluster = max(clusters_to_compare, 
                                 key=lambda c: (c.get('ranking_score', 0), c['created_at']))
                
                # Merge articles from other clusters into the best one
                for cluster_to_merge, similarity in similar_clusters:
                    if cluster_to_merge['id'] != best_cluster['id']:
                        # Check current size of target cluster
                        target_size_result = self.session.execute(text("""
                            SELECT COUNT(*) as count
                            FROM cluster.cluster_articles
                            WHERE cluster_id = :cluster_id
                        """), {'cluster_id': best_cluster['id']}).first()
                        
                        current_size = target_size_result.count if target_size_result else 0
                        
                        # Check size of source cluster
                        source_size_result = self.session.execute(text("""
                            SELECT COUNT(*) as count
                            FROM cluster.cluster_articles
                            WHERE cluster_id = :cluster_id
                        """), {'cluster_id': cluster_to_merge['id']}).first()
                        
                        source_size = source_size_result.count if source_size_result else 0
                        
                        # Only merge if it won't exceed max_cluster_size
                        if current_size + source_size <= self.max_cluster_size:
                            logger.info(f"Merging cluster {cluster_to_merge['cluster_uuid']} "
                                      f"into {best_cluster['cluster_uuid']} (similarity: {similarity:.3f})")
                            
                            # Move articles to the best cluster
                            self.session.execute(text("""
                                UPDATE cluster.cluster_articles 
                                SET cluster_id = :target_cluster_id
                                WHERE cluster_id = :source_cluster_id
                                AND NOT EXISTS (
                                    SELECT 1 FROM cluster.cluster_articles 
                                    WHERE cluster_id = :target_cluster_id 
                                    AND article_id = cluster.cluster_articles.article_id
                                )
                            """), {
                                'target_cluster_id': best_cluster['id'],
                                'source_cluster_id': cluster_to_merge['id']
                            })
                            # Deactivate the merged cluster
                            self.session.execute(text("""
                                UPDATE cluster.clusters 
                                SET is_active = false, updated_at = NOW()
                                WHERE id = :cluster_id
                            """), {'cluster_id': cluster_to_merge['id']})
                            
                            merged_count += 1
                            deactivated_count += 1
                        else:
                            logger.warning(f"Skipping merge of cluster {cluster_to_merge['cluster_uuid']} "
                                         f"into {best_cluster['cluster_uuid']}: would exceed max size "
                                         f"({current_size} + {source_size} > {self.max_cluster_size})")
                        
                        processed_clusters.add(cluster_to_merge['id'])
                
                processed_clusters.add(best_cluster['id'])
        
        # Commit all changes
        try:
            self.session.commit()
            logger.info(f"Cleanup complete: merged {merged_count} clusters, deactivated {deactivated_count}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            self.session.rollback()
            merged_count = 0
            deactivated_count = 0
        
        return {
            'clusters_merged': merged_count,
            'clusters_deactivated': deactivated_count
        }
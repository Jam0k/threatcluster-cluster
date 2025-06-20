# ThreatCluster Core

A sophisticated cybersecurity news aggregation and clustering system that automatically fetches, analyzes, and groups related security incidents from RSS feeds.

## Overview

ThreatCluster processes cybersecurity news from RSS feeds through a multi-stage pipeline:
1. **Feed Collection** - Fetches articles from RSS feeds with security filtering
2. **Entity Extraction** - Identifies threat actors, vulnerabilities, companies, and other entities
3. **Event Clustering** - Groups related articles using semantic similarity and entity matching
4. **Entity Refresh** - Discovers new threat actors and promotes frequently seen entities
5. **Ranking** - Scores clusters and articles based on criticality and relevance

## Workflow

```
RSS Feeds → Security Filter → Entity Extraction → Event Clustering → Ranking → Database
                                                         ↓
                                                 Entity Discovery
```

### Stage 1: Feed Collection
- Fetches articles from configured RSS feeds concurrently
- Applies security filtering to ensure relevance
- Extracts full content when RSS provides only summaries
- Handles image extraction from various RSS formats

### Stage 2: Entity Extraction
- **Threat Actors**: APT groups, ransomware gangs, malware families
- **Technical Indicators**: CVEs, domains, IPs, file hashes
- **Organizations**: Victim companies, security vendors
- **Attack Types**: MITRE tactics, vulnerability types
- Uses both regex patterns and SpaCy NER for comprehensive extraction

### Stage 3: Event Clustering
Two-phase clustering approach:
1. **Signature Matching**: Groups articles with identical event signatures (victim + threat actor + time)
2. **Semantic Clustering**: Uses CyberBERT (BAAI/bge-large-en-v1.5) for title similarity

Clustering rules:
- Same CVE + semantic similarity ≥ 0.60 → cluster
- High semantic similarity (≥ 0.74) + shared entities → cluster
- Flexible time windows based on entity matches (e.g., 72h for same CVE)

### Stage 4: Entity Refresh
- Discovers new threat actors from article text patterns
- Updates occurrence counts for all entities
- Promotes frequently seen entities (thresholds in config)
- Cleans up incorrectly extracted entities

### Stage 5: Ranking
Context-aware scoring system:
- **Base scores**: Cluster (100), Article (100)
- **Entity weights**: CVE exploited (150), Ransomware (100), Company as victim (100)
- **Critical keywords**: Zero-day (150), Critical (100), Actively exploited (120)
- **Multipliers**: Critical infrastructure (1.5x), Active exploitation (1.3x)
- **Source credibility**: CISA/US-CERT (1.5), Major vendors (1.2)

## Configuration

All settings are in `config.yaml`:

```yaml
# Processing settings
processing:
  max_workers: 10              # Concurrent feed fetchers
  batch_size: 50               # Articles per batch
  days_to_look_back: 14        # Clustering window
  fetch_interval_minutes: 10   # For continuous mode

# Clustering thresholds
clustering:
  semantic_similarity_threshold: 0.74
  entity_overlap_threshold: 0.4
  min_shared_entities: 3
  max_cluster_size: 5

# Entity weights for ranking
entities:
  weights:
    cve: 80
    ransomware_group: 100
    apt_group: 95
    company: 30
    
# Promotion thresholds
entities:
  promotion_thresholds:
    ransomware_group: 15    # Occurrences needed
    malware_family: 20
    other: 30
```

## Usage

### Basic Pipeline Run
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cluster.core import create_pipeline

# Create database session
engine = create_engine('postgresql://user:pass@localhost/threatcluster')
Session = sessionmaker(bind=engine)
session = Session()

# Create and run pipeline
pipeline = create_pipeline(session)
results = pipeline.run_full_pipeline()
```

### Individual Components
```python
# Just collect feeds
feed_results = pipeline.collect_feeds()

# Just cluster articles (last 7 days)
cluster_results = pipeline.cluster_articles(days_back=7)

# Just refresh entities
entity_results = pipeline.refresh_entities(days_back=30)

# Just update rankings
ranking_results = pipeline.update_rankings()
```

### Direct Component Usage
```python
from cluster.core import EntityExtractor, SecurityFilter

# Extract entities from text
extractor = EntityExtractor(session)
entities = extractor.extract_all("LockBit ransomware targets Acme Corp")
# Returns: {'ransomware_group': {'LockBit'}, 'company': {'Acme Corp'}}

# Check if article is security-relevant
filter = SecurityFilter()
is_security, score, reason = filter.is_security_article({
    'title': 'Critical Windows Vulnerability',
    'content': '...'
})
```

## Database Schema

### Key Tables
- `articles` - RSS feed articles with content and metadata
- `entities` - Threat actors, companies, CVEs, etc.
- `article_entities` - Links articles to extracted entities
- `clusters` - Groups of related articles
- `cluster_articles` - Articles in each cluster
- `cluster_shared_entities` - Common entities in clusters

### Entity Types
- `ransomware_group` - Ransomware operations
- `malware_family` - Malware variants
- `apt_group` - Advanced persistent threats
- `cve` - Vulnerability identifiers
- `company` - Organizations
- `other` - Victim organizations
- `domain`, `ip`, `email`, `file_hash` - IOCs

## Performance Optimizations

1. **Concurrent Processing**: Uses ThreadPoolExecutor for parallel feed fetching
2. **Batch Operations**: Processes articles in configurable batches
3. **Embedding Cache**: CyberBERT caches computed embeddings
4. **Database Indexes**: Optimized for common queries
5. **Incremental Updates**: Only processes new articles

## Security Features

1. **Content Filtering**: ~1700 security keywords for relevance
2. **HTML Sanitization**: Removes scripts and dangerous elements
3. **Entity Validation**: Cleans and validates extracted entities
4. **Source Credibility**: Weights sources by reliability

## Monitoring

The system logs detailed information:
- Feed fetch statistics
- Security filtering results
- Clustering decisions
- Entity discovery
- Ranking calculations

Check logs for:
- Articles filtered and reasons
- New entities discovered
- Clusters created/updated
- Ranking scores and factors

## Troubleshooting

### Low Article Count
- Check feed URLs are accessible
- Verify security filter isn't too aggressive
- Ensure feeds contain recent articles

### Poor Clustering
- Verify CyberBERT model is loaded
- Check entity extraction is working
- Review semantic similarity thresholds

### Missing Entities
- Check regex patterns in entity_extractor.py
- Verify SpaCy model is installed
- Review entity validation rules

### Ranking Issues
- Ensure entities are properly linked to articles
- Check source credibility scores
- Verify keyword weights

## Future Enhancements

1. **Intelligence Enrichment**: Integration with threat intelligence APIs
2. **Custom Entity Types**: User-defined entity categories
3. **Multi-language Support**: Process non-English feeds
4. **Real-time Alerts**: Notify on critical clusters
5. **API Endpoints**: RESTful API for cluster data
6. **Machine Learning**: Improve clustering with feedback
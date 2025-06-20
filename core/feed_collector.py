#!/usr/bin/env python3
"""
Feed Collection Module
Handles RSS feed fetching with security filtering and article processing
"""

import feedparser
import requests
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
from typing import List, Dict, Optional, Set, Tuple
import logging
from dateutil import parser as date_parser
import hashlib
from urllib.parse import urljoin, urlparse
import yaml
import os
from collections import defaultdict

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class FeedCollector:
    """Handles RSS feed collection and initial processing"""
    
    def __init__(self, session: Session, config_path: str = None):
        self.session = session
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize components
        self.security_filter = None
        self.entity_extractor = None
        self.image_extractor = ImageExtractor()
        
        # Statistics
        self.stats = {
            'total_fetched': 0,
            'security_relevant': 0,
            'filtered_out': 0,
            'reasons': defaultdict(int)
        }
        
        # Configuration
        self.max_articles_per_feed = self.config['processing']['max_articles_per_feed']
        self.max_workers = self.config['processing']['max_workers']
        self.feed_timeout = self.config['network']['feed_timeout']
        self.enable_filtering = self.config['security_filtering']['enabled']
    
    def set_components(self, security_filter, entity_extractor):
        """Set filter and extractor components"""
        self.security_filter = security_filter
        self.entity_extractor = entity_extractor
    
    def collect_all_feeds(self) -> List[Dict]:
        """Collect articles from all active feeds"""
        from cluster.database_connection import FeedRepository
        
        feed_repo = FeedRepository(self.session)
        feeds = feed_repo.get_active_feeds()
        
        if not feeds:
            logger.warning("No active feeds found")
            return []
        
        logger.info(f"Collecting from {len(feeds)} feeds")
        all_articles = []
        
        # Fetch feeds in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_feed = {
                executor.submit(self._fetch_single_feed, feed): feed 
                for feed in feeds
            }
            
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    articles, feed_stats = future.result()
                    all_articles.extend(articles)
                    
                    # Update statistics
                    self.stats['total_fetched'] += feed_stats['total']
                    self.stats['security_relevant'] += feed_stats['security']
                    self.stats['filtered_out'] += feed_stats['filtered']
                    
                except Exception as e:
                    logger.error(f"Error fetching {feed.name}: {e}")
        
        return all_articles
    
    def _fetch_single_feed(self, feed) -> Tuple[List[Dict], Dict]:
        """Fetch articles from a single RSS feed"""
        articles = []
        feed_stats = {'total': 0, 'security': 0, 'filtered': 0}
        
        logger.debug(f"Fetching RSS feed: {feed.url}")
        
        try:
            import socket
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.feed_timeout)
            
            # Parse feed
            feedparser.USER_AGENT = self.config['network']['user_agent']
            parsed_feed = feedparser.parse(feed.url)
            
            # Check status
            if hasattr(parsed_feed, 'status') and parsed_feed.status >= 400:
                logger.warning(f"Feed {feed.name} returned HTTP {parsed_feed.status}")
                print(f"  ⚠️ {feed.name}: HTTP {parsed_feed.status}")
                return [], feed_stats
            
            # Process entries
            for entry in parsed_feed.entries[:self.max_articles_per_feed]:
                title = entry.get('title', '').strip()
                url = entry.get('link', '').strip()
                
                if not title or not url:
                    continue
                
                # Extract content
                content = self._extract_content(entry)
                full_content = content
                
                # For sources with incomplete RSS, fetch full article
                if feed.name == 'Security Online' or (content and 'appeared first on' in content and len(content) < 500):
                    logger.debug(f"Fetching full content for: '{title[:50]}...'")
                    fetched_content = self.image_extractor.extract_article_content(url, content)
                    if fetched_content and len(fetched_content) > len(content):
                        full_content = fetched_content
                
                # Create preview for display
                preview_text = self._create_text_preview(full_content)
                if preview_text:
                    rss_content = f'<p>{preview_text}</p>\n<p><a href="{url}" target="_blank" rel="noopener noreferrer">Continue reading on {feed.name} →</a></p>'
                else:
                    rss_content = content
                
                # Extract image
                image_url = self.image_extractor.extract_from_rss_entry(entry)
                
                # Create article
                article = {
                    'title': title,
                    'content': rss_content,
                    'full_content': full_content,
                    'url': url,
                    'published': entry.get('published', ''),
                    'source': feed.name,
                    'feed_id': feed.id,
                    'image_url': image_url
                }
                
                feed_stats['total'] += 1
                
                # Apply security filtering if enabled
                if self.enable_filtering and self.security_filter:
                    filter_article = article.copy()
                    filter_article['content'] = article['full_content']
                    is_security, score, reason = self.security_filter.is_security_article(filter_article)
                    
                    if is_security:
                        article['security_score'] = score
                        articles.append(article)
                        feed_stats['security'] += 1
                    else:
                        feed_stats['filtered'] += 1
                        self.stats['reasons'][reason] += 1
                        logger.debug(f"Filtered: '{title[:50]}...' - {reason}")
                else:
                    articles.append(article)
                    feed_stats['security'] += 1
            
            if self.enable_filtering:
                print(f"  ✓ {feed.name}: {feed_stats['security']}/{feed_stats['total']} security articles")
            else:
                print(f"  ✓ {feed.name}: {len(articles)} articles fetched")
            
            socket.setdefaulttimeout(old_timeout)
            return articles, feed_stats
            
        except Exception as e:
            logger.error(f"Error fetching {feed.url}: {str(e)}")
            print(f"  ✗ Error fetching {feed.name}: {str(e)}")
            return [], feed_stats
    
    def _extract_content(self, entry) -> str:
        """Extract and clean content from RSS entry"""
        content = ''
        
        # Try content field first
        if hasattr(entry, 'content') and entry.content:
            if isinstance(entry.content, list) and len(entry.content) > 0:
                content = entry.content[0].get('value', '')
            elif hasattr(entry.content, 'value'):
                content = entry.content.value
        
        # Fallback to summary
        if not content:
            content = getattr(entry, 'summary', '') or getattr(entry, 'description', '')
        
        # Clean HTML
        if content and ('<' in content and '>' in content):
            try:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Remove dangerous elements
                for script in soup(["script", "style", "meta", "link"]):
                    script.decompose()
                
                # Remove media
                for tag in soup.find_all(["img", "iframe", "embed", "object", "video", "audio"]):
                    tag.decompose()
                
                # Clean attributes
                for tag in soup.find_all(True):
                    if tag.name == 'a':
                        href = tag.get('href')
                        tag.attrs = {'href': href} if href else {}
                    else:
                        tag.attrs = {}
                
                # Remove empty paragraphs
                for p in soup.find_all('p'):
                    if not p.get_text(strip=True):
                        p.decompose()
                
                # Keep only allowed tags
                allowed_tags = ['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'a', 'ul', 'ol', 'li',
                               'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'code']
                
                for tag in soup.find_all(True):
                    if tag.name not in allowed_tags:
                        tag.unwrap()
                
                content = str(soup).strip()
                
            except Exception as e:
                logger.debug(f"HTML parsing failed: {e}")
                content = BeautifulSoup(content, 'html.parser').get_text()
        
        return content
    
    def _create_text_preview(self, html_content: str, word_limit: int = 150) -> str:
        """Create text preview from HTML content"""
        if not html_content:
            return ""
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove scripts and styles
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text
            text = soup.get_text()
            
            # Clean whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            
            # Truncate
            words = text.split()
            if len(words) > word_limit:
                preview = ' '.join(words[:word_limit]) + '...'
            else:
                preview = ' '.join(words)
            
            # Escape HTML
            preview = preview.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            return preview
            
        except Exception as e:
            logger.debug(f"Error creating preview: {e}")
            return ""
    
    def save_articles(self, articles: List[Dict]) -> List:
        """Save articles to database with entity extraction"""
        from cluster.database_connection import ArticleRepository
        
        article_repo = ArticleRepository(self.session)
        saved_articles = []
        batch_size = self.config['processing']['batch_size']
        
        # Pre-fetch existing URLs
        urls = [article['url'] for article in articles]
        existing_urls = set()
        
        if urls:
            for i in range(0, len(urls), 1000):
                batch_urls = urls[i:i+1000]
                result = self.session.execute(text("""
                    SELECT url FROM cluster.articles WHERE url = ANY(:urls)
                """), {'urls': batch_urls})
                existing_urls.update(row[0] for row in result)
        
        print(f"\nProcessing {len(articles)} articles...")
        
        # Process in batches
        for i in range(0, len(articles), batch_size):
            batch = articles[i:i + batch_size]
            batch_saved = []
            
            for article_data in batch:
                try:
                    # Skip if exists
                    if article_data['url'] in existing_urls:
                        # Don't process existing articles
                        continue
                    
                    # Parse date
                    published_date = None
                    if article_data.get('published'):
                        try:
                            published_date = date_parser.parse(article_data['published'])
                        except:
                            pass
                    
                    # Create article
                    article = article_repo.create(
                        url=article_data['url'],
                        title=article_data['title'],
                        content=article_data.get('content'),
                        source=article_data['source'],
                        feed_id=article_data['feed_id'],
                        published_date=published_date,
                        image_url=article_data.get('image_url')
                    )
                    
                    # Skip if article creation failed (duplicate)
                    if not article:
                        continue
                    
                    # Store full content if different
                    if article_data.get('full_content') and article_data['full_content'] != article_data.get('content'):
                        self.session.execute(text("""
                            UPDATE cluster.articles 
                            SET full_content = :full_content 
                            WHERE id = :id
                        """), {'full_content': article_data['full_content'], 'id': article.id})
                    
                    # Extract and save entities
                    if self.entity_extractor and article:
                        article_text = f"{article.title} {article_data.get('full_content', article.content or '')}"
                        entities = self.entity_extractor.extract_all(article_text, source_url=article.url)
                        
                        if entities:
                            from cluster.database_connection import EntityRepository
                            entity_repo = EntityRepository(self.session)
                            entity_repo.link_entities_to_article(article.id, entities)
                        
                        # Mark as processed regardless of whether entities were found
                        article_repo.mark_as_processed(article.id)
                    
                    batch_saved.append(article)
                    existing_urls.add(article_data['url'])
                    
                except Exception as e:
                    logger.error(f"Error saving article {article_data.get('title', 'Unknown')}: {e}")
                    import traceback
                    traceback.print_exc()
            
            # Commit batch
            try:
                self.session.commit()
                saved_articles.extend(batch_saved)
                print(f"  Processed {min(i + batch_size, len(articles))}/{len(articles)} articles...")
            except Exception as e:
                logger.error(f"Error committing batch: {e}")
                self.session.rollback()
        
        return saved_articles


class ImageExtractor:
    """Extract images from RSS entries and article pages"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def extract_from_rss_entry(self, entry: Dict) -> Optional[str]:
        """Extract image URL from RSS entry"""
        try:
            # Check for media:content
            if hasattr(entry, 'media_content') and entry.media_content:
                for media in entry.media_content:
                    if media.get('type', '').startswith('image/'):
                        return media.get('url')
            
            # Check media:thumbnail
            if hasattr(entry, 'media_thumbnail') and entry.media_thumbnail:
                return entry.media_thumbnail[0].get('url')
            
            # Check enclosures
            if hasattr(entry, 'enclosures') and entry.enclosures:
                for enclosure in entry.enclosures:
                    if enclosure.get('type', '').startswith('image/'):
                        return enclosure.get('href') or enclosure.get('url')
            
            # Check content for images
            content = ''
            if hasattr(entry, 'content') and entry.content:
                if isinstance(entry.content, list) and len(entry.content) > 0:
                    content = entry.content[0].get('value', '')
                elif hasattr(entry.content, 'value'):
                    content = entry.content.value
            
            if not content and hasattr(entry, 'summary'):
                content = entry.summary
            
            if content:
                soup = BeautifulSoup(content, 'html.parser')
                img = soup.find('img')
                if img and img.get('src'):
                    src = img['src']
                    if src.startswith('http'):
                        return src
                    elif hasattr(entry, 'link') and entry.link:
                        return urljoin(entry.link, src)
            
            return None
            
        except Exception as e:
            logger.debug(f"Error extracting image from RSS: {e}")
            return None
    
    def extract_article_content(self, url: str, rss_content: str = '') -> str:
        """Extract full article content from webpage"""
        try:
            # Check if RSS content is sufficient
            is_footer_only = (
                'appeared first on' in rss_content and 
                len(rss_content) < 500 and
                rss_content.count('<p>') <= 2
            )
            
            if rss_content and len(rss_content) > 500 and not is_footer_only:
                return rss_content
            
            # Fetch from webpage
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            content = None
            
            # Security Online specific
            if 'securityonline.info' in url:
                article_content = soup.find('div', class_='entry-content') or soup.find('div', class_='content-inner')
                if article_content:
                    for elem in article_content.find_all(['script', 'style', 'ins', 'aside']):
                        elem.decompose()
                    for elem in article_content.find_all(class_=['sharedaddy', 'related-posts', 'jp-relatedposts']):
                        elem.decompose()
                    content = str(article_content)
            
            # Generic selectors
            if not content:
                selectors = [
                    'article .entry-content',
                    'article .content',
                    'main .content',
                    '.post-content',
                    '.article-content',
                    '.entry-content',
                    'article',
                    '[itemprop="articleBody"]'
                ]
                
                for selector in selectors:
                    elem = soup.select_one(selector)
                    if elem:
                        for tag in elem.find_all(['script', 'style', 'aside', 'nav']):
                            tag.decompose()
                        content = str(elem)
                        break
            
            # Clean content
            if content:
                content_soup = BeautifulSoup(content, 'html.parser')
                
                # Clean attributes
                for tag in content_soup.find_all(True):
                    if tag.name == 'a':
                        href = tag.get('href')
                        tag.attrs = {'href': href} if href else {}
                    else:
                        tag.attrs = {}
                
                # Remove empty paragraphs
                for p in content_soup.find_all('p'):
                    if not p.get_text(strip=True):
                        p.decompose()
                
                return str(content_soup)
            
            return rss_content
            
        except Exception as e:
            logger.debug(f"Error extracting article content from {url}: {e}")
            return rss_content
"""
News Ingestor - Fetches security news from RSS feeds and social sources.

Collects stories from multiple security news outlets, scores them based on
recency, impact, and buzz, then returns the top stories for podcast content.
"""

import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Set
from html import unescape

import requests

from ..utils import get_config, get_logger
from .models import Story, StoryType

logger = get_logger(__name__)


# RSS Feed sources with metadata
RSS_FEEDS = {
    "bleepingcomputer": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "weight": 1.2,  # Boost for high-quality source
    },
    "krebsonsecurity": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "weight": 1.3,  # High credibility
    },
    "therecord": {
        "name": "The Record",
        "url": "https://therecord.media/feed",
        "weight": 1.2,
    },
    "darkreading": {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "weight": 1.0,
    },
    "threatpost": {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "weight": 1.0,
    },
    "hackernews": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "weight": 1.1,
    },
    "securityweek": {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "weight": 1.0,
    },
    "schneier": {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "weight": 1.2,  # Influential analyst
    },
}

# Keywords for story classification
CLASSIFICATION_KEYWORDS = {
    StoryType.BREACH: [
        "breach", "leaked", "exposed", "compromised", "stolen data",
        "data leak", "hack attack", "million records", "customer data",
    ],
    StoryType.RANSOMWARE: [
        "ransomware", "ransom", "lockbit", "blackcat", "alphv", "clop",
        "encrypted files", "ransom demand", "double extortion",
    ],
    StoryType.APT: [
        "apt", "nation-state", "state-sponsored", "advanced persistent",
        "lazarus", "cozy bear", "fancy bear", "chinese hackers",
        "russian hackers", "north korean", "iranian hackers",
    ],
    StoryType.THREAT_INTEL: [
        "malware", "trojan", "botnet", "phishing campaign", "zero-day",
        "exploit", "threat actor", "attack campaign", "ioc", "ttps",
    ],
    StoryType.VULNERABILITY: [
        "cve-", "vulnerability", "patch", "security update", "rce",
        "remote code execution", "privilege escalation", "critical flaw",
    ],
    StoryType.INDUSTRY: [
        "acquisition", "funding", "startup", "market", "regulation",
        "compliance", "gdpr", "fine", "lawsuit", "ciso", "security team",
    ],
}

# High-impact keywords that boost score
IMPACT_KEYWORDS = {
    "critical": 25,
    "zero-day": 30,
    "actively exploited": 35,
    "millions": 20,
    "billions": 25,
    "government": 15,
    "hospital": 20,
    "healthcare": 15,
    "bank": 20,
    "financial": 15,
    "infrastructure": 25,
    "supply chain": 25,
    "widespread": 20,
    "emergency": 25,
    "cisa": 20,
    "fbi": 15,
    "nsa": 15,
}


def fetch_news_stories(
    hours: int = 24,
    max_stories: int = 20,
    sources: Optional[List[str]] = None,
) -> List[Story]:
    """
    Fetch and score news stories from configured RSS feeds.

    Args:
        hours: How many hours back to search (default 24)
        max_stories: Maximum number of stories to return
        sources: List of source keys to fetch from (None = all)

    Returns:
        List of Story objects, sorted by final_score descending
    """
    config = get_config()
    all_stories: List[Story] = []
    seen_urls: Set[str] = set()

    # Filter sources if specified
    feeds_to_fetch = RSS_FEEDS
    if sources:
        feeds_to_fetch = {k: v for k, v in RSS_FEEDS.items() if k in sources}

    logger.info(f"Fetching news from {len(feeds_to_fetch)} sources...")

    for source_key, feed_config in feeds_to_fetch.items():
        try:
            stories = _fetch_rss_feed(
                source_key=source_key,
                feed_url=feed_config["url"],
                source_name=feed_config["name"],
                weight=feed_config.get("weight", 1.0),
                hours=hours,
            )

            # Deduplicate by URL
            for story in stories:
                if story.url not in seen_urls:
                    seen_urls.add(story.url)
                    all_stories.append(story)

            logger.info(f"  {feed_config['name']}: {len(stories)} stories")

            # Be nice to servers
            time.sleep(0.5)

        except Exception as e:
            logger.warning(f"Failed to fetch {feed_config['name']}: {e}")

    # Score all stories
    logger.info(f"Scoring {len(all_stories)} stories...")
    for story in all_stories:
        _score_story(story, hours)

    # Sort by final score and return top N
    all_stories.sort(key=lambda s: s.final_score, reverse=True)

    logger.info(f"Top story: {all_stories[0].title if all_stories else 'None'}")

    return all_stories[:max_stories]


def _fetch_rss_feed(
    source_key: str,
    feed_url: str,
    source_name: str,
    weight: float,
    hours: int,
) -> List[Story]:
    """
    Fetch and parse a single RSS feed.

    Args:
        source_key: Internal source identifier
        feed_url: URL of the RSS feed
        source_name: Human-readable source name
        weight: Quality weight for this source
        hours: How many hours back to include

    Returns:
        List of Story objects from this feed
    """
    headers = {
        "User-Agent": "SecurityPodcastBot/1.0 (https://github.com/example/podcast)",
    }

    response = requests.get(feed_url, headers=headers, timeout=15)
    response.raise_for_status()

    # Parse XML
    content = response.text
    stories = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Extract items (works for both RSS and Atom)
    items = _extract_feed_items(content)

    for item in items:
        # Parse publication date
        pub_date = _parse_date(item.get("pubDate") or item.get("published") or item.get("updated"))

        # Skip old stories
        if pub_date and pub_date < cutoff:
            continue

        title = _clean_html(item.get("title", ""))
        link = item.get("link", "")
        summary = _clean_html(item.get("description") or item.get("summary") or "")

        if not title or not link:
            continue

        # Generate unique ID from URL
        story_id = hashlib.md5(link.encode()).hexdigest()[:12]

        # Classify story type
        story_type = _classify_story(title, summary)

        # Extract CVE mentions
        mentioned_cves = _extract_cves(title + " " + summary)

        story = Story(
            id=story_id,
            title=title,
            summary=summary[:500],  # Truncate long summaries
            url=link,
            story_type=story_type,
            source=source_key,
            source_name=source_name,
            author=item.get("author", ""),
            published_date=pub_date,
            fetched_at=datetime.now(timezone.utc),
            mentioned_cves=mentioned_cves,
        )

        stories.append(story)

    return stories


def _extract_feed_items(content: str) -> List[Dict]:
    """
    Extract items from RSS/Atom feed XML.

    Simple regex-based parsing (avoids heavy XML dependencies).
    """
    items = []

    # Try RSS format first (<item>)
    item_matches = re.findall(r"<item[^>]*>(.*?)</item>", content, re.DOTALL | re.IGNORECASE)

    if not item_matches:
        # Try Atom format (<entry>)
        item_matches = re.findall(r"<entry[^>]*>(.*?)</entry>", content, re.DOTALL | re.IGNORECASE)

    for item_content in item_matches:
        item = {}

        # Extract common fields
        title_match = re.search(r"<title[^>]*>(.*?)</title>", item_content, re.DOTALL | re.IGNORECASE)
        if title_match:
            item["title"] = title_match.group(1).strip()

        # Link can be in different formats
        link_match = re.search(r"<link[^>]*href=[\"']([^\"']+)[\"']", item_content, re.IGNORECASE)
        if not link_match:
            link_match = re.search(r"<link[^>]*>(.*?)</link>", item_content, re.DOTALL | re.IGNORECASE)
        if link_match:
            item["link"] = link_match.group(1).strip()

        # Description/summary
        desc_match = re.search(r"<description[^>]*>(.*?)</description>", item_content, re.DOTALL | re.IGNORECASE)
        if desc_match:
            item["description"] = desc_match.group(1).strip()

        summary_match = re.search(r"<summary[^>]*>(.*?)</summary>", item_content, re.DOTALL | re.IGNORECASE)
        if summary_match:
            item["summary"] = summary_match.group(1).strip()

        # Publication date
        pubdate_match = re.search(r"<pubDate[^>]*>(.*?)</pubDate>", item_content, re.DOTALL | re.IGNORECASE)
        if pubdate_match:
            item["pubDate"] = pubdate_match.group(1).strip()

        published_match = re.search(r"<published[^>]*>(.*?)</published>", item_content, re.DOTALL | re.IGNORECASE)
        if published_match:
            item["published"] = published_match.group(1).strip()

        updated_match = re.search(r"<updated[^>]*>(.*?)</updated>", item_content, re.DOTALL | re.IGNORECASE)
        if updated_match:
            item["updated"] = updated_match.group(1).strip()

        # Author
        author_match = re.search(r"<author[^>]*>(?:<name>)?(.*?)(?:</name>)?</author>", item_content, re.DOTALL | re.IGNORECASE)
        if author_match:
            item["author"] = _clean_html(author_match.group(1).strip())

        if item.get("title") and item.get("link"):
            items.append(item)

    return items


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse various date formats from RSS feeds."""
    if not date_str:
        return None

    date_str = date_str.strip()

    # Common formats
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",      # RFC 822
        "%a, %d %b %Y %H:%M:%S %Z",      # RFC 822 with named timezone
        "%Y-%m-%dT%H:%M:%S%z",           # ISO 8601
        "%Y-%m-%dT%H:%M:%SZ",            # ISO 8601 UTC
        "%Y-%m-%d %H:%M:%S",             # Simple datetime
        "%Y-%m-%d",                       # Simple date
    ]

    # Handle timezone offsets without colon (e.g., +0000)
    date_str = re.sub(r"(\d{2})(\d{2})$", r"\1:\2", date_str)

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Try parsing with timezone name (GMT, EST, etc.)
    try:
        # Remove timezone name and parse
        cleaned = re.sub(r"\s+[A-Z]{2,4}$", "", date_str)
        for fmt in formats:
            try:
                dt = datetime.strptime(cleaned, fmt.replace(" %z", "").replace(" %Z", ""))
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    except Exception:
        pass

    logger.debug(f"Could not parse date: {date_str}")
    return None


def _clean_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    if not text:
        return ""

    # Handle CDATA
    text = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", text, flags=re.DOTALL)

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Decode HTML entities
    text = unescape(text)

    # Clean whitespace
    text = " ".join(text.split())

    return text.strip()


def _classify_story(title: str, summary: str) -> StoryType:
    """Classify story type based on keywords in title and summary."""
    text = (title + " " + summary).lower()

    # Check each category
    scores = {}
    for story_type, keywords in CLASSIFICATION_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[story_type] = score

    if not scores:
        return StoryType.GENERAL

    # Return highest-scoring category
    return max(scores, key=scores.get)


def _extract_cves(text: str) -> List[str]:
    """Extract CVE IDs from text."""
    pattern = r"CVE-\d{4}-\d{4,7}"
    matches = re.findall(pattern, text.upper())
    return list(set(matches))


def _score_story(story: Story, hours: int) -> None:
    """
    Calculate all score components for a story.

    Modifies the story object in place.
    """
    # Recency score (0-100)
    # Full points for stories in last 2 hours, linear decay to 0 at cutoff
    story.recency_score = _calculate_recency_score(story.published_date, hours)

    # Impact score (0-100)
    story.impact_score = _calculate_impact_score(story)

    # Buzz score (0-100)
    # For now, use heuristics. Later can integrate social API
    story.buzz_score = _calculate_buzz_score(story)

    # Calculate weighted final score
    story.calculate_final_score()


def _calculate_recency_score(pub_date: Optional[datetime], hours: int) -> float:
    """Calculate recency score based on publication time."""
    if not pub_date:
        return 50.0  # Unknown = middle score

    now = datetime.now(timezone.utc)
    if pub_date.tzinfo is None:
        pub_date = pub_date.replace(tzinfo=timezone.utc)

    age_hours = (now - pub_date).total_seconds() / 3600

    if age_hours < 0:
        return 100.0  # Future date = fresh
    if age_hours > hours:
        return 0.0

    # Linear decay with boost for very recent
    if age_hours < 2:
        return 100.0
    elif age_hours < 6:
        return 90.0 - (age_hours - 2) * 5
    else:
        # Linear from 70 at 6h to 0 at cutoff
        return max(0, 70 * (1 - (age_hours - 6) / (hours - 6)))


def _calculate_impact_score(story: Story) -> float:
    """Calculate impact score based on content signals."""
    score = 30.0  # Base score

    text = (story.title + " " + story.summary).lower()

    # Check impact keywords
    for keyword, points in IMPACT_KEYWORDS.items():
        if keyword in text:
            score += points

    # Story type bonuses
    type_bonuses = {
        StoryType.BREACH: 15,
        StoryType.RANSOMWARE: 20,
        StoryType.APT: 25,
        StoryType.THREAT_INTEL: 10,
        StoryType.VULNERABILITY: 15,
    }
    score += type_bonuses.get(story.story_type, 0)

    # CVE mentions indicate technical significance
    score += len(story.mentioned_cves) * 5

    # Cap at 100
    return min(100.0, score)


def _calculate_buzz_score(story: Story) -> float:
    """
    Calculate buzz/engagement score.

    Currently uses heuristics. Can be enhanced with social API integration.
    """
    score = 20.0  # Base score

    # Source credibility bonus
    credibility_bonuses = {
        "krebsonsecurity": 30,
        "bleepingcomputer": 25,
        "therecord": 25,
        "schneier": 30,
        "hackernews": 20,
    }
    score += credibility_bonuses.get(story.source, 10)

    # Title engagement signals
    title_lower = story.title.lower()
    engagement_signals = [
        ("breaking", 15),
        ("exclusive", 10),
        ("revealed", 10),
        ("major", 10),
        ("massive", 10),
        ("urgent", 15),
    ]
    for signal, points in engagement_signals:
        if signal in title_lower:
            score += points

    # Actual social metrics would be added here
    if story.reddit_score > 0:
        score += min(30, story.reddit_score / 10)

    if story.social_shares > 0:
        score += min(30, story.social_shares / 100)

    return min(100.0, score)


def fetch_reddit_security(
    subreddits: List[str] = None,
    hours: int = 24,
    max_posts: int = 10,
) -> List[Story]:
    """
    Fetch top posts from security-related subreddits.

    Args:
        subreddits: List of subreddits to fetch (default: netsec, cybersecurity)
        hours: How many hours back to search
        max_posts: Maximum posts to return

    Returns:
        List of Story objects from Reddit
    """
    if subreddits is None:
        subreddits = ["netsec", "cybersecurity"]

    stories = []
    seen_urls: Set[str] = set()

    headers = {
        "User-Agent": "SecurityPodcastBot/1.0",
    }

    for subreddit in subreddits:
        try:
            # Use Reddit JSON API (no auth required for public data)
            url = f"https://www.reddit.com/r/{subreddit}/hot.json?limit=25"
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()
            posts = data.get("data", {}).get("children", [])

            for post in posts:
                post_data = post.get("data", {})

                # Skip stickied/pinned posts
                if post_data.get("stickied"):
                    continue

                # Check age
                created = datetime.fromtimestamp(post_data.get("created_utc", 0), tz=timezone.utc)
                cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
                if created < cutoff:
                    continue

                url = post_data.get("url", "")
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Generate story
                story_id = hashlib.md5(url.encode()).hexdigest()[:12]

                story = Story(
                    id=story_id,
                    title=post_data.get("title", ""),
                    summary=post_data.get("selftext", "")[:500],
                    url=url,
                    story_type=_classify_story(post_data.get("title", ""), post_data.get("selftext", "")),
                    source=f"reddit_{subreddit}",
                    source_name=f"r/{subreddit}",
                    author=post_data.get("author", ""),
                    published_date=created,
                    fetched_at=datetime.now(timezone.utc),
                    reddit_score=post_data.get("score", 0),
                    mentioned_cves=_extract_cves(post_data.get("title", "") + " " + post_data.get("selftext", "")),
                )

                # Score story
                _score_story(story, hours)
                stories.append(story)

            logger.info(f"  r/{subreddit}: {len([s for s in stories if s.source == f'reddit_{subreddit}'])} posts")
            time.sleep(1)  # Reddit rate limiting

        except Exception as e:
            logger.warning(f"Failed to fetch r/{subreddit}: {e}")

    # Sort by final score
    stories.sort(key=lambda s: s.final_score, reverse=True)
    return stories[:max_posts]


def deduplicate_stories(stories: List[Story], similarity_threshold: float = 0.7) -> List[Story]:
    """
    Remove duplicate/similar stories based on title similarity.

    Args:
        stories: List of stories to deduplicate
        similarity_threshold: Jaccard similarity threshold for duplicates (0-1)

    Returns:
        Deduplicated list of stories
    """
    if not stories:
        return []

    unique = []
    seen_titles: List[Set[str]] = []

    for story in stories:
        # Tokenize title
        title_tokens = set(story.title.lower().split())

        # Check similarity with existing titles
        is_duplicate = False
        for seen in seen_titles:
            if not seen or not title_tokens:
                continue

            # Jaccard similarity
            intersection = len(title_tokens & seen)
            union = len(title_tokens | seen)
            similarity = intersection / union if union > 0 else 0

            if similarity >= similarity_threshold:
                is_duplicate = True
                break

        if not is_duplicate:
            unique.append(story)
            seen_titles.append(title_tokens)

    logger.info(f"Deduplication: {len(stories)} -> {len(unique)} stories")
    return unique


def generate_mock_stories(count: int = 5) -> List[Story]:
    """Generate mock stories for testing without API calls."""
    mock_data = [
        {
            "title": "Major Healthcare Provider Reports Data Breach Affecting 2.3 Million Patients",
            "summary": "A leading healthcare organization has disclosed a significant data breach that exposed personal and medical information of millions of patients.",
            "type": StoryType.BREACH,
            "source": "bleepingcomputer",
            "impact": 85,
        },
        {
            "title": "New LockBit Ransomware Variant Targets Critical Infrastructure",
            "summary": "Security researchers have identified a new variant of LockBit ransomware specifically designed to target industrial control systems.",
            "type": StoryType.RANSOMWARE,
            "source": "therecord",
            "impact": 90,
        },
        {
            "title": "Chinese APT Group Exploits Zero-Day in Popular Enterprise Software",
            "summary": "A sophisticated threat actor linked to China has been observed exploiting a previously unknown vulnerability in widely-used enterprise software.",
            "type": StoryType.APT,
            "source": "krebsonsecurity",
            "impact": 95,
        },
        {
            "title": "CISA Warns of Active Exploitation of Critical Cisco Vulnerability",
            "summary": "The Cybersecurity and Infrastructure Security Agency has added a critical Cisco vulnerability to its Known Exploited Vulnerabilities catalog.",
            "type": StoryType.VULNERABILITY,
            "source": "securityweek",
            "impact": 80,
        },
        {
            "title": "Major Cloud Provider Acquires Security Startup for $2 Billion",
            "summary": "In a significant move for the cybersecurity industry, a leading cloud provider has announced the acquisition of a promising security startup.",
            "type": StoryType.INDUSTRY,
            "source": "darkreading",
            "impact": 40,
        },
    ]

    stories = []
    now = datetime.now(timezone.utc)

    for i, data in enumerate(mock_data[:count]):
        story_id = hashlib.md5(data["title"].encode()).hexdigest()[:12]

        story = Story(
            id=story_id,
            title=data["title"],
            summary=data["summary"],
            url=f"https://example.com/story-{i}",
            story_type=data["type"],
            source=data["source"],
            source_name=RSS_FEEDS.get(data["source"], {}).get("name", data["source"]),
            published_date=now - timedelta(hours=i * 2),
            fetched_at=now,
            recency_score=100 - (i * 15),
            impact_score=data["impact"],
            buzz_score=70 - (i * 10),
        )
        story.calculate_final_score()
        stories.append(story)

    return stories

"""
RSS/Podcast Feed Generator - Creates and updates podcast RSS feeds.

Generates a valid podcast RSS feed compatible with:
- Apple Podcasts
- Spotify
- Google Podcasts
- Other podcast apps

The feed is updated each time a new episode is published.
"""

import os
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional
from xml.dom import minidom

from ..utils import get_config, get_logger

logger = get_logger(__name__)


# Podcast metadata (configure in config.yaml)
DEFAULT_PODCAST_CONFIG = {
    "title": "Daily Security Brief",
    "description": "Your daily cybersecurity vulnerability briefing. Critical CVEs, patches, and threat intel delivered in under 10 minutes.",
    "author": "Security Brief Team",
    "email": "podcast@example.com",
    "website": "https://example.com/podcast",
    "image_url": "https://example.com/podcast-cover.jpg",
    "language": "en-us",
    "category": "Technology",
    "subcategory": "Tech News",
    "explicit": "no",
}


def generate_rss_feed(
    episodes: list,
    output_path: str = "output/podcast.xml",
    podcast_config: dict = None,
) -> str:
    """
    Generate a complete podcast RSS feed.

    Args:
        episodes: List of episode dicts with keys:
            - title: Episode title
            - description: Episode description
            - audio_url: URL to MP3 file
            - duration_seconds: Audio duration
            - published_date: ISO datetime string
            - episode_number: Optional episode number
        output_path: Where to save the RSS XML
        podcast_config: Override default podcast metadata

    Returns:
        Path to generated RSS file
    """
    config = podcast_config or DEFAULT_PODCAST_CONFIG

    # Create RSS root
    rss = ET.Element("rss")
    rss.set("version", "2.0")
    rss.set("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd")
    rss.set("xmlns:content", "http://purl.org/rss/1.0/modules/content/")
    rss.set("xmlns:atom", "http://www.w3.org/2005/Atom")

    channel = ET.SubElement(rss, "channel")

    # Channel metadata
    ET.SubElement(channel, "title").text = config["title"]
    ET.SubElement(channel, "description").text = config["description"]
    ET.SubElement(channel, "language").text = config.get("language", "en-us")
    ET.SubElement(channel, "link").text = config.get("website", "")

    # Atom self-link (required by some validators)
    atom_link = ET.SubElement(channel, "atom:link")
    atom_link.set("href", config.get("feed_url", f"{config.get('website', '')}/podcast.xml"))
    atom_link.set("rel", "self")
    atom_link.set("type", "application/rss+xml")

    # iTunes-specific tags
    ET.SubElement(channel, "itunes:author").text = config.get("author", "")
    ET.SubElement(channel, "itunes:summary").text = config["description"]
    ET.SubElement(channel, "itunes:explicit").text = config.get("explicit", "no")

    # Owner info
    owner = ET.SubElement(channel, "itunes:owner")
    ET.SubElement(owner, "itunes:name").text = config.get("author", "")
    ET.SubElement(owner, "itunes:email").text = config.get("email", "")

    # Cover image
    image = ET.SubElement(channel, "itunes:image")
    image.set("href", config.get("image_url", ""))

    # Category
    category = ET.SubElement(channel, "itunes:category")
    category.set("text", config.get("category", "Technology"))
    if config.get("subcategory"):
        subcat = ET.SubElement(category, "itunes:category")
        subcat.set("text", config["subcategory"])

    # Add episodes
    for ep in episodes:
        item = ET.SubElement(channel, "item")

        ET.SubElement(item, "title").text = ep["title"]
        ET.SubElement(item, "description").text = ep.get("description", "")

        # Enclosure (the actual audio file)
        enclosure = ET.SubElement(item, "enclosure")
        enclosure.set("url", ep["audio_url"])
        enclosure.set("type", "audio/mpeg")
        enclosure.set("length", str(ep.get("file_size", 0)))

        # GUID (unique identifier)
        guid = ET.SubElement(item, "guid")
        guid.set("isPermaLink", "false")
        guid.text = ep.get("guid") or ep["audio_url"]

        # Publication date
        if ep.get("published_date"):
            pub_date = _parse_date(ep["published_date"])
            ET.SubElement(item, "pubDate").text = _format_rfc822(pub_date)

        # iTunes-specific
        ET.SubElement(item, "itunes:duration").text = _format_duration(ep.get("duration_seconds", 0))
        ET.SubElement(item, "itunes:summary").text = ep.get("description", "")[:4000]
        ET.SubElement(item, "itunes:explicit").text = "no"

        if ep.get("episode_number"):
            ET.SubElement(item, "itunes:episode").text = str(ep["episode_number"])

    # Pretty print
    xml_str = ET.tostring(rss, encoding="unicode")
    pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

    # Remove extra blank lines
    lines = [line for line in pretty_xml.split("\n") if line.strip()]
    pretty_xml = "\n".join(lines)

    # Write to file
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(pretty_xml, encoding="utf-8")

    logger.info(f"Generated RSS feed: {output_path} ({len(episodes)} episodes)")
    return str(output_file)


def update_rss_feed(
    episode: dict,
    feed_path: str = "output/podcast.xml",
    max_episodes: int = 100,
) -> str:
    """
    Add a new episode to an existing RSS feed.

    Args:
        episode: Episode dict (same format as generate_rss_feed)
        feed_path: Path to existing RSS feed
        max_episodes: Maximum episodes to keep in feed

    Returns:
        Path to updated RSS file
    """
    feed_file = Path(feed_path)

    if not feed_file.exists():
        logger.info("No existing feed found, creating new one")
        return generate_rss_feed([episode], feed_path)

    # Parse existing feed
    tree = ET.parse(feed_file)
    root = tree.getroot()
    channel = root.find("channel")

    if channel is None:
        logger.error("Invalid RSS feed structure")
        return generate_rss_feed([episode], feed_path)

    # Create new item element
    item = ET.Element("item")

    ET.SubElement(item, "title").text = episode["title"]
    ET.SubElement(item, "description").text = episode.get("description", "")

    enclosure = ET.SubElement(item, "enclosure")
    enclosure.set("url", episode["audio_url"])
    enclosure.set("type", "audio/mpeg")
    enclosure.set("length", str(episode.get("file_size", 0)))

    guid = ET.SubElement(item, "guid")
    guid.set("isPermaLink", "false")
    guid.text = episode.get("guid") or episode["audio_url"]

    if episode.get("published_date"):
        pub_date = _parse_date(episode["published_date"])
        ET.SubElement(item, "pubDate").text = _format_rfc822(pub_date)

    ET.SubElement(item, "itunes:duration").text = _format_duration(episode.get("duration_seconds", 0))
    ET.SubElement(item, "itunes:summary").text = episode.get("description", "")[:4000]
    ET.SubElement(item, "itunes:explicit").text = "no"

    # Insert new episode at the top (after channel metadata, before other items)
    items = channel.findall("item")
    if items:
        # Insert before first item
        first_item_index = list(channel).index(items[0])
        channel.insert(first_item_index, item)
    else:
        channel.append(item)

    # Remove old episodes if over limit
    items = channel.findall("item")
    while len(items) > max_episodes:
        channel.remove(items[-1])
        items = channel.findall("item")

    # Write updated feed
    tree.write(feed_file, encoding="unicode", xml_declaration=True)

    logger.info(f"Updated RSS feed: {feed_path} (now {len(channel.findall('item'))} episodes)")
    return str(feed_file)


def generate_episode_rss_entry(
    episode_date: str,
    audio_url: str,
    audio_path: str,
    vulnerabilities: list,
    stories: list = None,
    episode_number: int = None,
) -> dict:
    """
    Generate RSS episode entry from episode data.

    Args:
        episode_date: Date string (YYYY-MM-DD)
        audio_url: Public URL to the MP3 file
        audio_path: Local path to MP3 for file size
        vulnerabilities: List of Vulnerability objects
        stories: List of Story objects
        episode_number: Optional episode number

    Returns:
        Episode dict ready for RSS feed
    """
    date_obj = datetime.strptime(episode_date, "%Y-%m-%d")
    date_formatted = date_obj.strftime("%B %d, %Y")

    # Generate title
    critical_count = sum(1 for v in vulnerabilities if v.priority and v.priority.value == "CRITICAL")

    if critical_count > 0:
        title = f"CRITICAL: {critical_count} Urgent Patches - {date_formatted}"
    else:
        title = f"Daily Security Brief - {date_formatted}"

    # Generate description
    desc_parts = [f"Security briefing for {date_formatted}.", ""]

    if vulnerabilities:
        desc_parts.append("Vulnerabilities covered:")
        for v in vulnerabilities[:5]:
            desc_parts.append(f"- {v.cve_id}: {v.title or v.vendor + ' ' + v.product}")

    if stories:
        desc_parts.extend(["", "News stories:"])
        for s in stories[:3]:
            desc_parts.append(f"- {s.title[:80]}")

    description = "\n".join(desc_parts)

    # Get file size
    file_size = 0
    if audio_path and Path(audio_path).exists():
        file_size = Path(audio_path).stat().st_size

    # Get duration from audio manifest if available
    duration_seconds = 0
    manifest_path = Path(audio_path).parent / "audio_manifest.json"
    if manifest_path.exists():
        import json
        with open(manifest_path) as f:
            manifest = json.load(f)
            duration_seconds = manifest.get("duration_seconds", 0)

    return {
        "title": title,
        "description": description,
        "audio_url": audio_url,
        "file_size": file_size,
        "duration_seconds": duration_seconds,
        "published_date": datetime.now().isoformat(),
        "guid": f"daily-security-brief-{episode_date}",
        "episode_number": episode_number,
    }


def _parse_date(date_str: str) -> datetime:
    """Parse ISO date string to datetime."""
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now()


def _format_rfc822(dt: datetime) -> str:
    """Format datetime as RFC 822 (required for RSS)."""
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _format_duration(seconds: int) -> str:
    """Format duration as HH:MM:SS."""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    else:
        return f"{minutes}:{secs:02d}"

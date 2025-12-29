"""
Blog Publisher - Create blog posts for episodes.

Supports:
- WordPress (REST API)
- Ghost (Admin API)
- Markdown file generation (for static sites)
"""

import json
import hashlib
import hmac
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from ..utils import get_config, get_logger

logger = get_logger(__name__)


def create_blog_post(
    episode_date: str,
    title: str,
    content: str,
    youtube_url: str = None,
    audio_url: str = None,
    vulnerabilities: list = None,
    stories: list = None,
    platform: str = "wordpress",
) -> dict:
    """
    Create a blog post for an episode.

    Args:
        episode_date: Date string (YYYY-MM-DD)
        title: Post title
        content: HTML or markdown content
        youtube_url: Optional YouTube embed URL
        audio_url: Optional audio player URL
        vulnerabilities: List of Vulnerability objects for metadata
        stories: List of Story objects for metadata
        platform: "wordpress", "ghost", or "markdown"

    Returns:
        Dict with post URL and ID
    """
    config = get_config()
    blog_config = config.get("blog", {})

    if platform == "wordpress":
        return _create_wordpress_post(title, content, youtube_url, audio_url, blog_config)
    elif platform == "ghost":
        return _create_ghost_post(title, content, youtube_url, audio_url, blog_config)
    elif platform == "markdown":
        return _create_markdown_post(episode_date, title, content, youtube_url, audio_url, vulnerabilities, stories)
    else:
        raise ValueError(f"Unknown platform: {platform}")


def generate_blog_content(
    episode_date: str,
    vulnerabilities: list,
    stories: list = None,
    youtube_url: str = None,
    audio_url: str = None,
) -> dict:
    """
    Generate blog post title and content from episode data.

    Args:
        episode_date: Date string (YYYY-MM-DD)
        vulnerabilities: List of Vulnerability objects
        stories: List of Story objects
        youtube_url: YouTube video URL
        audio_url: Audio file URL

    Returns:
        Dict with title and content (HTML)
    """
    date_obj = datetime.strptime(episode_date, "%Y-%m-%d")
    date_formatted = date_obj.strftime("%B %d, %Y")

    # Generate title
    critical_count = sum(1 for v in vulnerabilities if v.priority and v.priority.value == "CRITICAL")

    if critical_count > 0:
        title = f"CRITICAL: {critical_count} Urgent Patches Today - {date_formatted}"
    else:
        title = f"Daily Security Brief - {date_formatted}"

    # Build HTML content
    html_parts = []

    # Embed YouTube if available
    if youtube_url:
        video_id = _extract_youtube_id(youtube_url)
        if video_id:
            html_parts.append(f'''
<div class="video-embed">
    <iframe width="560" height="315"
            src="https://www.youtube.com/embed/{video_id}"
            frameborder="0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowfullscreen>
    </iframe>
</div>
''')

    # Audio player if available
    if audio_url:
        html_parts.append(f'''
<div class="audio-player">
    <audio controls>
        <source src="{audio_url}" type="audio/mpeg">
        Your browser does not support the audio element.
    </audio>
</div>
''')

    # Introduction
    html_parts.append(f"<p>Today's security briefing for {date_formatted}.</p>")

    # Vulnerabilities section
    if vulnerabilities:
        html_parts.append("<h2>Vulnerabilities</h2>")

        for v in vulnerabilities:
            priority = v.priority.value if v.priority else "UNKNOWN"
            priority_class = priority.lower()

            html_parts.append(f'''
<div class="vulnerability {priority_class}">
    <h3><span class="priority-badge {priority_class}">{priority}</span> {v.cve_id}</h3>
    <p><strong>{v.title or v.vendor + ' ' + v.product}</strong></p>
    <ul>
        <li><strong>CVSS:</strong> {v.cvss_score}</li>
        <li><strong>Vendor:</strong> {v.vendor}</li>
        <li><strong>Product:</strong> {v.product}</li>
        <li><strong>Affected:</strong> {v.affected_versions or 'See advisory'}</li>
    </ul>
    <p>{v.description[:500]}{'...' if len(v.description) > 500 else ''}</p>
    {f'<p><a href="{v.remediation_url}" target="_blank">View Advisory</a></p>' if v.remediation_url else ''}
</div>
''')

    # News section
    if stories:
        html_parts.append("<h2>Security News</h2>")

        for s in stories:
            html_parts.append(f'''
<div class="news-story">
    <h3>{s.title}</h3>
    <p class="source">Source: {s.source_name}</p>
    <p>{s.summary}</p>
    <p><a href="{s.url}" target="_blank">Read full story</a></p>
</div>
''')

    # Call to action
    html_parts.append('''
<div class="cta">
    <p><strong>Stay patched, stay paranoid.</strong></p>
    <p>Subscribe to our podcast for daily security updates.</p>
</div>
''')

    return {
        "title": title,
        "content": "\n".join(html_parts),
    }


def _create_wordpress_post(
    title: str,
    content: str,
    youtube_url: str,
    audio_url: str,
    config: dict,
) -> dict:
    """Create a post on WordPress using REST API."""
    api_url = config.get("wordpress_url", "").rstrip("/")
    username = config.get("wordpress_user", "")
    password = config.get("wordpress_app_password", "")  # Application password

    if not all([api_url, username, password]):
        logger.warning("WordPress not configured, skipping blog post")
        return {"status": "skipped", "reason": "not_configured"}

    endpoint = f"{api_url}/wp-json/wp/v2/posts"

    # Prepare post data
    post_data = {
        "title": title,
        "content": content,
        "status": "publish",
        "categories": config.get("wordpress_categories", []),
        "tags": config.get("wordpress_tags", []),
    }

    try:
        response = requests.post(
            endpoint,
            json=post_data,
            auth=(username, password),
            timeout=30,
        )
        response.raise_for_status()

        result = response.json()
        logger.info(f"WordPress post created: {result.get('link')}")

        return {
            "status": "published",
            "post_id": result["id"],
            "url": result["link"],
            "platform": "wordpress",
        }

    except Exception as e:
        logger.error(f"WordPress post failed: {e}")
        return {"status": "error", "error": str(e)}


def _create_ghost_post(
    title: str,
    content: str,
    youtube_url: str,
    audio_url: str,
    config: dict,
) -> dict:
    """Create a post on Ghost using Admin API."""
    api_url = config.get("ghost_url", "").rstrip("/")
    api_key = config.get("ghost_admin_key", "")

    if not all([api_url, api_key]):
        logger.warning("Ghost not configured, skipping blog post")
        return {"status": "skipped", "reason": "not_configured"}

    # Parse admin key (format: id:secret)
    try:
        key_id, key_secret = api_key.split(":")
    except ValueError:
        logger.error("Invalid Ghost admin key format (should be id:secret)")
        return {"status": "error", "error": "invalid_key_format"}

    # Generate JWT token for Ghost Admin API
    token = _generate_ghost_token(key_id, key_secret)

    endpoint = f"{api_url}/ghost/api/admin/posts/"

    # Ghost uses mobiledoc format
    mobiledoc = {
        "version": "0.3.1",
        "atoms": [],
        "cards": [["html", {"html": content}]],
        "markups": [],
        "sections": [[10, 0]],
    }

    post_data = {
        "posts": [{
            "title": title,
            "mobiledoc": json.dumps(mobiledoc),
            "status": "published",
            "tags": config.get("ghost_tags", []),
        }]
    }

    try:
        response = requests.post(
            endpoint,
            json=post_data,
            headers={"Authorization": f"Ghost {token}"},
            timeout=30,
        )
        response.raise_for_status()

        result = response.json()
        post = result["posts"][0]
        logger.info(f"Ghost post created: {post.get('url')}")

        return {
            "status": "published",
            "post_id": post["id"],
            "url": post["url"],
            "platform": "ghost",
        }

    except Exception as e:
        logger.error(f"Ghost post failed: {e}")
        return {"status": "error", "error": str(e)}


def _generate_ghost_token(key_id: str, key_secret: str) -> str:
    """Generate JWT token for Ghost Admin API."""
    import base64

    # Decode the secret
    secret = bytes.fromhex(key_secret)

    # Create header and payload
    header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + 300,  # 5 minutes
        "aud": "/admin/",
    }

    # Encode
    def b64_encode(data):
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b"=").decode()

    header_b64 = b64_encode(header)
    payload_b64 = b64_encode(payload)

    # Sign
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret, message, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _create_markdown_post(
    episode_date: str,
    title: str,
    content: str,
    youtube_url: str,
    audio_url: str,
    vulnerabilities: list,
    stories: list,
) -> dict:
    """Create a markdown file for static site generators."""
    output_dir = Path("output/blog")
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{episode_date}-daily-security-brief.md"
    filepath = output_dir / filename

    # Build frontmatter
    frontmatter = {
        "title": title,
        "date": episode_date,
        "tags": ["security", "vulnerabilities", "daily-brief"],
        "youtube": youtube_url,
        "audio": audio_url,
    }

    # Convert HTML to simple markdown
    md_content = _html_to_markdown(content)

    # Write file
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("---\n")
        for key, value in frontmatter.items():
            if value:
                if isinstance(value, list):
                    f.write(f"{key}:\n")
                    for item in value:
                        f.write(f"  - {item}\n")
                else:
                    f.write(f'{key}: "{value}"\n')
        f.write("---\n\n")
        f.write(md_content)

    logger.info(f"Markdown post created: {filepath}")

    return {
        "status": "created",
        "path": str(filepath),
        "platform": "markdown",
    }


def _html_to_markdown(html: str) -> str:
    """Simple HTML to Markdown conversion."""
    import re

    md = html

    # Headers
    md = re.sub(r"<h1[^>]*>(.*?)</h1>", r"# \1", md)
    md = re.sub(r"<h2[^>]*>(.*?)</h2>", r"## \1", md)
    md = re.sub(r"<h3[^>]*>(.*?)</h3>", r"### \1", md)

    # Bold/italic
    md = re.sub(r"<strong>(.*?)</strong>", r"**\1**", md)
    md = re.sub(r"<em>(.*?)</em>", r"*\1*", md)

    # Links
    md = re.sub(r'<a href="([^"]*)"[^>]*>(.*?)</a>', r"[\2](\1)", md)

    # Lists
    md = re.sub(r"<li>(.*?)</li>", r"- \1", md)
    md = re.sub(r"</?ul[^>]*>", "", md)

    # Paragraphs
    md = re.sub(r"<p>(.*?)</p>", r"\1\n", md)

    # Remove other tags
    md = re.sub(r"<[^>]+>", "", md)

    # Clean up whitespace
    md = re.sub(r"\n{3,}", "\n\n", md)

    return md.strip()


def _extract_youtube_id(url: str) -> Optional[str]:
    """Extract video ID from YouTube URL."""
    import re

    patterns = [
        r"(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})",
        r"youtube\.com/embed/([a-zA-Z0-9_-]{11})",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    return None

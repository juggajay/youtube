"""
YouTube Publisher - Upload videos using YouTube Data API v3.

Handles OAuth2 authentication and video uploads with automatic token refresh.

Setup:
1. Create a project at console.cloud.google.com
2. Enable YouTube Data API v3
3. Create OAuth 2.0 credentials (Desktop app)
4. Download credentials as client_secrets.json
5. Run authenticate_youtube() once to get refresh token

Usage:
    from src.publish.youtube import upload_to_youtube, authenticate_youtube

    # First time setup (requires browser)
    authenticate_youtube()

    # Then upload (fully automated)
    result = upload_to_youtube(
        video_path="output/episodes/2025-01-15/episode.mp4",
        title="Daily Security Brief - Jan 15, 2025",
        description="Today's vulnerabilities and security news...",
    )
"""

import json
import os
import pickle
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)

# Scopes required for uploading videos
YOUTUBE_SCOPES = [
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube",
]

# Token storage location
TOKEN_PATH = Path("data/youtube_token.pickle")
CLIENT_SECRETS_PATH = Path("data/client_secrets.json")


def is_youtube_authenticated() -> bool:
    """Check if we have valid or refreshable YouTube credentials."""
    if not TOKEN_PATH.exists():
        return False

    try:
        with open(TOKEN_PATH, "rb") as f:
            creds = pickle.load(f)
        # Valid if token is valid OR if we have a refresh token
        return creds and (creds.valid or creds.refresh_token)
    except Exception:
        return False


def _get_youtube_credentials():
    """Get YouTube credentials, refreshing if necessary."""
    from google.auth.transport.requests import Request

    if not TOKEN_PATH.exists():
        return None

    with open(TOKEN_PATH, "rb") as f:
        creds = pickle.load(f)

    # Refresh if expired
    if creds and not creds.valid and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Save refreshed token
            with open(TOKEN_PATH, "wb") as f:
                pickle.dump(creds, f)
            logger.info("YouTube token refreshed successfully")
        except Exception as e:
            logger.error(f"Failed to refresh token: {e}")
            return None

    return creds


def authenticate_youtube(client_secrets_path: str = None) -> bool:
    """
    Authenticate with YouTube OAuth2.

    This requires a browser for the initial authorization.
    After first run, tokens are stored and refreshed automatically.

    Args:
        client_secrets_path: Path to client_secrets.json from Google Cloud Console

    Returns:
        True if authentication successful
    """
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
    except ImportError:
        logger.error("Install google packages: pip install google-auth-oauthlib google-api-python-client")
        return False

    secrets_path = Path(client_secrets_path) if client_secrets_path else CLIENT_SECRETS_PATH

    if not secrets_path.exists():
        logger.error(f"Client secrets not found at {secrets_path}")
        logger.info("Download from Google Cloud Console: APIs & Services > Credentials")
        return False

    creds = None

    # Check for existing token
    if TOKEN_PATH.exists():
        with open(TOKEN_PATH, "rb") as f:
            creds = pickle.load(f)

    # Refresh or get new credentials
    if creds and creds.expired and creds.refresh_token:
        logger.info("Refreshing YouTube credentials...")
        creds.refresh(Request())
    elif not creds or not creds.valid:
        logger.info("Starting YouTube OAuth flow...")
        logger.info("A browser window will open. Log in and authorize the app.")

        flow = InstalledAppFlow.from_client_secrets_file(
            str(secrets_path),
            scopes=YOUTUBE_SCOPES
        )
        creds = flow.run_local_server(port=8080)

    # Save credentials
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(TOKEN_PATH, "wb") as f:
        pickle.dump(creds, f)

    logger.info("YouTube authentication successful!")
    return True


def _get_youtube_service():
    """Get authenticated YouTube API service."""
    try:
        from googleapiclient.discovery import build
    except ImportError:
        raise ImportError("Install: pip install google-api-python-client google-auth-oauthlib")

    creds = _get_youtube_credentials()
    if not creds:
        raise RuntimeError("Not authenticated. Run authenticate_youtube() first.")

    return build("youtube", "v3", credentials=creds)


def upload_to_youtube(
    video_path: str,
    title: str,
    description: str,
    tags: list = None,
    category_id: str = "28",  # Science & Technology
    privacy_status: str = "public",
    playlist_id: str = None,
    thumbnail_path: str = None,
    publish_at: str = None,
) -> dict:
    """
    Upload a video to YouTube.

    Args:
        video_path: Path to the video file
        title: Video title (max 100 chars)
        description: Video description (max 5000 chars)
        tags: List of tags (max 500 chars total)
        category_id: YouTube category (28 = Science & Technology)
        privacy_status: "public", "private", or "unlisted"
        playlist_id: Optional playlist to add video to
        thumbnail_path: Optional custom thumbnail
        publish_at: ISO 8601 datetime for scheduled publish (requires privacy="private")

    Returns:
        Dict with video_id, url, and status
    """
    try:
        from googleapiclient.http import MediaFileUpload
    except ImportError:
        raise ImportError("Install: pip install google-api-python-client")

    video_file = Path(video_path)
    if not video_file.exists():
        raise FileNotFoundError(f"Video not found: {video_path}")

    youtube = _get_youtube_service()

    # Prepare metadata
    body = {
        "snippet": {
            "title": title[:100],
            "description": description[:5000],
            "tags": tags or [],
            "categoryId": category_id,
        },
        "status": {
            "privacyStatus": privacy_status,
            "selfDeclaredMadeForKids": False,
        },
    }

    # Handle scheduled publishing
    if publish_at:
        body["status"]["privacyStatus"] = "private"
        body["status"]["publishAt"] = publish_at

    logger.info(f"Uploading to YouTube: {title}")
    logger.info(f"File: {video_path} ({video_file.stat().st_size / 1024 / 1024:.1f} MB)")

    # Create upload request
    media = MediaFileUpload(
        str(video_file),
        mimetype="video/mp4",
        resumable=True,
        chunksize=10 * 1024 * 1024,  # 10MB chunks
    )

    request = youtube.videos().insert(
        part="snippet,status",
        body=body,
        media_body=media,
    )

    # Execute upload with progress
    response = None
    while response is None:
        status, response = request.next_chunk()
        if status:
            progress = int(status.progress() * 100)
            logger.info(f"Upload progress: {progress}%")

    video_id = response["id"]
    video_url = f"https://www.youtube.com/watch?v={video_id}"

    logger.info(f"Upload complete! Video ID: {video_id}")
    logger.info(f"URL: {video_url}")

    # Set custom thumbnail if provided
    if thumbnail_path and Path(thumbnail_path).exists():
        try:
            _set_thumbnail(youtube, video_id, thumbnail_path)
        except Exception as e:
            logger.warning(f"Failed to set thumbnail: {e}")

    # Add to playlist if specified
    if playlist_id:
        try:
            _add_to_playlist(youtube, video_id, playlist_id)
        except Exception as e:
            logger.warning(f"Failed to add to playlist: {e}")

    return {
        "video_id": video_id,
        "url": video_url,
        "status": response["status"]["privacyStatus"],
        "title": response["snippet"]["title"],
    }


def _set_thumbnail(youtube, video_id: str, thumbnail_path: str) -> None:
    """Set custom thumbnail for a video."""
    from googleapiclient.http import MediaFileUpload

    logger.info(f"Setting thumbnail: {thumbnail_path}")

    media = MediaFileUpload(thumbnail_path, mimetype="image/png")
    youtube.thumbnails().set(
        videoId=video_id,
        media_body=media,
    ).execute()

    logger.info("Thumbnail set successfully")


def _add_to_playlist(youtube, video_id: str, playlist_id: str) -> None:
    """Add video to a playlist."""
    logger.info(f"Adding to playlist: {playlist_id}")

    youtube.playlistItems().insert(
        part="snippet",
        body={
            "snippet": {
                "playlistId": playlist_id,
                "resourceId": {
                    "kind": "youtube#video",
                    "videoId": video_id,
                }
            }
        }
    ).execute()

    logger.info("Added to playlist successfully")


def generate_youtube_metadata(
    episode_date: str,
    vulnerabilities: list,
    stories: list = None,
    use_llm: bool = True,
    audio_manifest: dict = None,
) -> dict:
    """
    Generate YouTube title, description, and tags from episode content.

    Uses LLM-based SEO optimization when available, falls back to simple generation.

    Args:
        episode_date: Date string (YYYY-MM-DD)
        vulnerabilities: List of Vulnerability objects
        stories: List of Story objects
        use_llm: Whether to use LLM for metadata generation
        audio_manifest: Optional audio manifest for chapter markers

    Returns:
        Dict with title, description, tags
    """
    # Try LLM-based generation first
    if use_llm:
        try:
            from .metadata import generate_youtube_metadata as llm_metadata
            from .metadata import format_description_for_youtube

            # Build daily_brief format for the LLM
            daily_brief = {
                "date": episode_date,
                "vulnerabilities": [
                    {
                        "cve_id": v.cve_id,
                        "title": v.title,
                        "vendor": v.vendor,
                        "product": v.product,
                        "cvss_score": v.cvss_score,
                        "priority": v.priority.value if v.priority else "UNKNOWN",
                        "description": v.description[:300] if v.description else "",
                    }
                    for v in vulnerabilities
                ],
                "filter_stats": {
                    "critical_count": sum(1 for v in vulnerabilities if v.priority and v.priority.value == "CRITICAL"),
                    "high_count": sum(1 for v in vulnerabilities if v.priority and v.priority.value == "HIGH"),
                },
            }

            # Prepare stories for LLM
            story_data = []
            if stories:
                for s in stories[:5]:
                    story_data.append({
                        "title": s.title,
                        "summary": s.summary[:200] if s.summary else "",
                        "story_type": s.story_type.value if hasattr(s.story_type, 'value') else str(s.story_type),
                    })

            # Generate metadata with LLM
            meta = llm_metadata(daily_brief, stories=story_data)

            # Format description with chapters
            if audio_manifest:
                meta["description"] = format_description_for_youtube(meta, audio_manifest)

            return {
                "title": meta.get("primary_title", meta.get("titles", ["Security Brief"])[0])[:100],
                "description": meta.get("description", "")[:5000],
                "tags": meta.get("tags", [])[:30],
            }

        except Exception as e:
            logger.warning(f"LLM metadata generation failed, using fallback: {e}")

    # Fallback: Simple rule-based generation
    return _generate_simple_metadata(episode_date, vulnerabilities, stories)


def _generate_simple_metadata(
    episode_date: str,
    vulnerabilities: list,
    stories: list = None,
) -> dict:
    """
    Simple rule-based metadata generation (fallback).
    """
    date_obj = datetime.strptime(episode_date, "%Y-%m-%d")
    date_formatted = date_obj.strftime("%B %d, %Y")
    date_short = date_obj.strftime("%b %d")

    critical_count = sum(1 for v in vulnerabilities if v.priority and v.priority.value == "CRITICAL")
    high_count = sum(1 for v in vulnerabilities if v.priority and v.priority.value == "HIGH")

    # Generate title
    if critical_count > 0:
        title = f"CRITICAL: {critical_count} Urgent Patches | Daily Security Brief {date_short}"
    elif high_count > 0:
        title = f"{high_count} High-Severity Vulns | Daily Security Brief {date_short}"
    else:
        title = f"Daily Security Brief | {date_formatted}"

    # Generate description
    desc_parts = [
        f"Daily Security Brief for {date_formatted}",
        "",
        "Today's vulnerabilities:",
    ]

    for v in vulnerabilities[:5]:
        priority = v.priority.value if v.priority else "UNKNOWN"
        desc_parts.append(f"- [{priority}] {v.cve_id}: {v.title or v.vendor + ' ' + v.product}")

    if stories:
        desc_parts.extend(["", "Security news:"])
        for s in stories[:3]:
            desc_parts.append(f"- {s.title[:60]}...")

    desc_parts.extend([
        "",
        "---",
        "Subscribe for daily cybersecurity updates.",
        "Covering CVEs, patches, breaches, and threat intel.",
        "",
        "Hosted by AI Analysts Alec & Melody.",
        "",
        "#cybersecurity #infosec #vulnerabilities #cve #patching",
    ])

    description = "\n".join(desc_parts)

    # Generate tags
    tags = [
        "cybersecurity", "infosec", "security", "vulnerabilities", "CVE",
        "patching", "threat intelligence", "daily brief", "security news",
    ]

    vendors = set(v.vendor.lower() for v in vulnerabilities if v.vendor)
    for vendor in list(vendors)[:5]:
        if vendor and len(vendor) > 2:
            tags.append(vendor)

    return {
        "title": title[:100],
        "description": description[:5000],
        "tags": tags[:30],
    }


def create_or_get_playlist(playlist_name: str, description: str = "") -> str:
    """
    Get existing playlist by name or create a new one.

    Args:
        playlist_name: Name of the playlist
        description: Description for new playlist

    Returns:
        Playlist ID
    """
    youtube = _get_youtube_service()

    # Search for existing playlist
    response = youtube.playlists().list(
        part="snippet",
        mine=True,
        maxResults=50,
    ).execute()

    for item in response.get("items", []):
        if item["snippet"]["title"] == playlist_name:
            logger.info(f"Found existing playlist: {playlist_name}")
            return item["id"]

    # Create new playlist
    logger.info(f"Creating playlist: {playlist_name}")
    response = youtube.playlists().insert(
        part="snippet,status",
        body={
            "snippet": {
                "title": playlist_name,
                "description": description,
            },
            "status": {
                "privacyStatus": "public",
            }
        }
    ).execute()

    return response["id"]

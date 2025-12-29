"""
Publishing module for distributing episodes to various platforms.

Supports:
- YouTube (video upload with OAuth)
- RSS/Podcast feed generation
- Blog post creation (WordPress/Ghost)
"""

from .youtube import (
    upload_to_youtube,
    authenticate_youtube,
    is_youtube_authenticated,
)
from .rss import generate_rss_feed, update_rss_feed
from .blog import create_blog_post

__all__ = [
    "upload_to_youtube",
    "authenticate_youtube",
    "is_youtube_authenticated",
    "generate_rss_feed",
    "update_rss_feed",
    "create_blog_post",
]

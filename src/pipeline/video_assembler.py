"""
Video Assembler - Creates YouTube video using FFmpeg.

Automatically detects GitHub Actions and downgrades to 1080p for speed.
Uses -tune stillimage for optimal static background encoding.
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)


def get_video_settings():
    """
    Returns resolution and FFmpeg preset based on environment.
    GitHub Actions runners are too weak for 4K.
    """
    if os.getenv("GITHUB_ACTIONS") == "true":
        logger.info("Detected GitHub Actions: Using 1080p for speed")
        return {
            "width": 1920,
            "height": 1080,
            "preset": "ultrafast",
            "crf": "28"
        }
    else:
        # Local Machine (High Quality)
        logger.info("Local environment: Using 4K quality")
        return {
            "width": 3840,
            "height": 2160,
            "preset": "medium",
            "crf": "18"
        }


def assemble_video(
    audio_manifest: dict,
    script: dict,
    output_dir: str,
    background_image: Optional[str] = None,
    font_path: Optional[str] = None,
) -> dict:
    """
    Assemble video from audio with static background.

    Args:
        audio_manifest: audio_manifest.json structure
        script: episode_script.json structure
        output_dir: Directory to save video files
        background_image: Path to background image
        font_path: Path to .ttf font file (unused in simplified version)

    Returns:
        video_manifest.json structure
    """
    config = get_config()
    settings = get_video_settings()

    episode_date = audio_manifest["episode_date"]
    audio_file = audio_manifest["audio_file"]

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Default background path
    if not background_image:
        background_image = str(Path(config.get("paths", {}).get("assets", "assets")) / "background.png")

    if not os.path.exists(background_image):
        raise FileNotFoundError(f"Background image missing: {background_image}")

    # Output file
    resolution_tag = f"{settings['width']}x{settings['height']}"
    output_file = str(output_path / f"episode_{episode_date}_{resolution_tag}.mp4")

    # FFmpeg Command
    cmd = [
        "ffmpeg", "-y",
        "-loop", "1",
        "-i", background_image,
        "-i", audio_file,
        "-c:v", "libx264",
        "-tune", "stillimage",
        "-preset", settings["preset"],
        "-crf", settings["crf"],
        "-c:a", "aac",
        "-b:a", "192k",
        "-vf", f"scale={settings['width']}:{settings['height']}:force_original_aspect_ratio=decrease,pad={settings['width']}:{settings['height']}:(ow-iw)/2:(oh-ih)/2,format=yuv420p",
        "-shortest",
        "-movflags", "+faststart",
        output_file
    ]

    logger.info(f"Running FFmpeg video assembly...")
    logger.info(f"Resolution: {resolution_tag}, Preset: {settings['preset']}")

    try:
        # 20 minute timeout for long episodes
        result = subprocess.run(
            cmd,
            check=True,
            timeout=1200,
            capture_output=True,
            text=True
        )
        logger.info(f"Video assembled: {output_file}")

    except subprocess.TimeoutExpired:
        logger.error("FFmpeg timed out after 20 minutes")
        raise RuntimeError("FFmpeg encoding timeout")

    except subprocess.CalledProcessError as e:
        logger.error(f"FFmpeg failed: {e.stderr}")
        raise RuntimeError(f"FFmpeg encoding failed: {e.stderr}")

    # Get file size
    file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
    logger.info(f"Video size: {file_size_mb:.1f} MB")

    # Create manifest
    manifest = {
        "episode_date": episode_date,
        "video_file": output_file,
        "resolution": resolution_tag,
        "duration_seconds": audio_manifest.get("duration_seconds", 0),
        "file_size_mb": round(file_size_mb, 2),
        "settings": settings,
        "sources": {
            "audio_manifest": "audio_manifest.json",
            "background": background_image
        }
    }

    # Save manifest
    manifest_path = output_path / "video_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest

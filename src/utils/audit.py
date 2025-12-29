"""
Episode Auditor - Pre-publish validation to catch silent audio, black frames, corrupt files.

The "Idiot Check" - runs before uploading to prevent:
- Silent/empty audio (TTS API failures)
- Black screen videos (FFmpeg path errors)
- Corrupt/incomplete renders
- Videos too short for mid-roll ads

Automatically adjusts thresholds for GitHub Actions (1080p) vs Local (4K).

Usage:
    python -m src.utils.audit output/episodes/2025-01-01/episode_2025-01-01_1920x1080.mp4
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import get_logger

logger = get_logger(__name__)


def get_audit_thresholds():
    """
    Returns audit thresholds based on environment.
    GitHub Actions uses 1080p with lower bitrate, so file sizes are smaller.
    """
    if os.getenv("GITHUB_ACTIONS") == "true":
        logger.info("Detected GitHub Actions: Using 1080p thresholds")
        return {
            "min_duration_sec": 120,  # 2 minutes minimum
            "min_size_mb": 5.0,       # 1080p ultrafast CRF 28 = smaller files
        }
    else:
        logger.info("Local environment: Using 4K thresholds")
        return {
            "min_duration_sec": 180,  # 3 minutes minimum
            "min_size_mb": 50.0,      # 4K medium CRF 18 = larger files
        }


def get_media_info(file_path: str) -> dict:
    """
    Get JSON metadata from ffprobe.

    Args:
        file_path: Path to video/audio file

    Returns:
        Dict with format and stream info
    """
    cmd = [
        "ffprobe",
        "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        file_path
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise ValueError(f"ffprobe failed: {result.stderr}")

    return json.loads(result.stdout)


def detect_silence(file_path: str, threshold_db: float = -50) -> bool:
    """
    Check if audio is consistently below threshold (silent).

    Uses ffmpeg volumedetect filter to analyze mean volume.

    Args:
        file_path: Path to audio/video file
        threshold_db: Volume threshold in dB (default -50)

    Returns:
        True if audio is silent (below threshold)
    """
    # Use NUL on Windows, /dev/null on Unix
    null_device = "NUL" if sys.platform == "win32" else "/dev/null"

    cmd = [
        "ffmpeg",
        "-i", file_path,
        "-af", "volumedetect",
        "-vn", "-sn", "-dn",
        "-f", "null",
        null_device
    ]

    # FFmpeg writes volumedetect stats to stderr
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stderr

    # Parse mean_volume from output
    match = re.search(r"mean_volume:\s*([\-\d\.]+)\s*dB", output)
    if match:
        mean_vol = float(match.group(1))
        logger.debug(f"Mean volume: {mean_vol} dB")
        # If mean volume is incredibly low (e.g., -90dB), it's silent
        return mean_vol < threshold_db

    # If we can't parse volume, assume failure
    logger.warning("Could not parse volume from ffmpeg output")
    return True


def detect_black_frames(file_path: str, sample_count: int = 5) -> bool:
    """
    Check if video contains mostly black frames.

    Samples frames throughout the video and checks average brightness.

    Args:
        file_path: Path to video file
        sample_count: Number of frames to sample

    Returns:
        True if video appears to be mostly black
    """
    try:
        info = get_media_info(file_path)
        duration = float(info['format']['duration'])

        # Sample frames at intervals
        black_count = 0
        for i in range(sample_count):
            timestamp = (duration / (sample_count + 1)) * (i + 1)

            # Extract frame and check mean brightness
            cmd = [
                "ffmpeg",
                "-ss", str(timestamp),
                "-i", file_path,
                "-vframes", "1",
                "-vf", "blackdetect=d=0:pix_th=0.1",
                "-f", "null",
                "NUL" if sys.platform == "win32" else "/dev/null"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if "black_start" in result.stderr:
                black_count += 1

        # If more than half the samples are black, fail
        return black_count > (sample_count / 2)

    except Exception as e:
        logger.warning(f"Black frame detection failed: {e}")
        return False


def audit_episode(
    video_path: str,
    min_duration_sec: int = None,
    min_size_mb: float = None,
    silence_threshold_db: float = -60,
) -> dict:
    """
    Main episode auditor. Validates video before upload.

    Checks:
    1. File exists and is readable
    2. Container is valid (ffprobe can read it)
    3. Duration meets minimum
    4. Has audio stream
    5. Audio is not silent
    6. File size is reasonable

    Thresholds auto-adjust for GitHub Actions (1080p) vs Local (4K).

    Args:
        video_path: Path to the video file
        min_duration_sec: Minimum duration in seconds (auto-detected if None)
        min_size_mb: Minimum file size in MB (auto-detected if None)
        silence_threshold_db: Volume threshold for silence detection

    Returns:
        Dict with audit results

    Raises:
        FileNotFoundError: Video file doesn't exist
        ValueError: Video fails any quality check
    """
    # Get environment-appropriate thresholds
    thresholds = get_audit_thresholds()
    if min_duration_sec is None:
        min_duration_sec = thresholds["min_duration_sec"]
    if min_size_mb is None:
        min_size_mb = thresholds["min_size_mb"]

    logger.info(f"Auditing: {os.path.basename(video_path)}")
    logger.info(f"Thresholds: min_duration={min_duration_sec}s, min_size={min_size_mb}MB")

    results = {
        "file": video_path,
        "passed": False,
        "checks": {},
    }

    # Check 1: File exists
    if not os.path.exists(video_path):
        raise FileNotFoundError(f"Video file missing: {video_path}")
    results["checks"]["file_exists"] = True

    # Check 2: Container validity (can ffprobe read it?)
    try:
        info = get_media_info(video_path)
        results["checks"]["container_valid"] = True
    except Exception as e:
        raise ValueError(f"Corrupt video file (ffprobe failed): {e}")

    # Check 3: Duration
    duration = float(info['format']['duration'])
    results["duration_seconds"] = duration
    results["duration_minutes"] = round(duration / 60, 2)

    if duration < min_duration_sec:
        raise ValueError(
            f"Video too short: {duration:.1f}s (minimum: {min_duration_sec}s)"
        )
    results["checks"]["duration"] = True
    logger.info(f"Duration: {duration/60:.2f} mins")

    # Check 4: Audio stream exists
    audio_streams = [s for s in info['streams'] if s['codec_type'] == 'audio']
    if not audio_streams:
        raise ValueError("No audio stream found in video")
    results["checks"]["has_audio"] = True
    results["audio_codec"] = audio_streams[0].get("codec_name", "unknown")

    # Check 5: Audio is not silent
    if detect_silence(video_path, threshold_db=silence_threshold_db):
        raise ValueError(
            f"Audio is silent (mean volume < {silence_threshold_db}dB)"
        )
    results["checks"]["audio_levels"] = True
    logger.info("Audio levels: OK")

    # Check 6: File size (catches black screen / failed renders)
    size_bytes = os.path.getsize(video_path)
    size_mb = size_bytes / (1024 * 1024)
    results["size_mb"] = round(size_mb, 2)

    if size_mb < min_size_mb:
        raise ValueError(
            f"File size suspiciously small: {size_mb:.2f} MB (minimum: {min_size_mb} MB). "
            "Render likely failed or produced black frames."
        )
    results["checks"]["file_size"] = True
    logger.info(f"File size: {size_mb:.2f} MB")

    # Check 7: Video stream exists and has reasonable resolution
    video_streams = [s for s in info['streams'] if s['codec_type'] == 'video']
    if video_streams:
        width = video_streams[0].get("width", 0)
        height = video_streams[0].get("height", 0)
        results["resolution"] = f"{width}x{height}"

        if width < 1280 or height < 720:
            logger.warning(f"Low resolution: {width}x{height}")
        results["checks"]["has_video"] = True

    # All checks passed
    results["passed"] = True
    logger.info("AUDIT PASSED - Ready for upload")

    return results


def audit_thumbnail(thumbnail_path: str, min_size_kb: float = 10) -> dict:
    """
    Validate thumbnail before upload.

    Checks:
    1. File exists
    2. Is valid image (can be read)
    3. Has reasonable dimensions (1280x720 recommended)
    4. File size is reasonable

    Args:
        thumbnail_path: Path to thumbnail image
        min_size_kb: Minimum file size in KB

    Returns:
        Dict with audit results
    """
    logger.info(f"Auditing thumbnail: {os.path.basename(thumbnail_path)}")

    results = {
        "file": thumbnail_path,
        "passed": False,
        "checks": {},
    }

    if not os.path.exists(thumbnail_path):
        raise FileNotFoundError(f"Thumbnail missing: {thumbnail_path}")
    results["checks"]["file_exists"] = True

    # Check file size
    size_bytes = os.path.getsize(thumbnail_path)
    size_kb = size_bytes / 1024
    results["size_kb"] = round(size_kb, 2)

    if size_kb < min_size_kb:
        raise ValueError(f"Thumbnail too small: {size_kb:.2f} KB")
    results["checks"]["file_size"] = True

    # Check dimensions with ffprobe
    try:
        info = get_media_info(thumbnail_path)
        streams = info.get("streams", [])
        if streams:
            width = streams[0].get("width", 0)
            height = streams[0].get("height", 0)
            results["resolution"] = f"{width}x{height}"

            if width != 1280 or height != 720:
                logger.warning(f"Thumbnail not 1280x720: {width}x{height}")
            results["checks"]["dimensions"] = True
    except Exception as e:
        logger.warning(f"Could not verify thumbnail dimensions: {e}")

    results["passed"] = True
    logger.info("Thumbnail audit PASSED")

    return results


def full_episode_audit(episode_dir: str) -> dict:
    """
    Run full audit on all episode assets.

    Checks video, audio, and thumbnail.

    Args:
        episode_dir: Path to episode output directory

    Returns:
        Dict with all audit results
    """
    episode_path = Path(episode_dir)
    results = {
        "episode_dir": str(episode_path),
        "passed": False,
        "video": None,
        "thumbnail": None,
    }

    # Find video file (check for both 4K and 1080p patterns)
    video_files = list(episode_path.glob("*_3840x2160.mp4"))  # 4K
    if not video_files:
        video_files = list(episode_path.glob("*_1920x1080.mp4"))  # 1080p
    if not video_files:
        video_files = list(episode_path.glob("*_4K.mp4"))  # Legacy 4K naming
    if not video_files:
        video_files = list(episode_path.glob("*.mp4"))  # Any MP4

    if video_files:
        try:
            results["video"] = audit_episode(str(video_files[0]))
        except Exception as e:
            results["video"] = {"passed": False, "error": str(e)}
            raise

    # Find thumbnail
    thumbnail_path = episode_path / "thumbnail.png"
    if thumbnail_path.exists():
        try:
            results["thumbnail"] = audit_thumbnail(str(thumbnail_path))
        except Exception as e:
            results["thumbnail"] = {"passed": False, "error": str(e)}
            logger.warning(f"Thumbnail audit failed: {e}")

    # Overall pass/fail
    results["passed"] = (
        results.get("video", {}).get("passed", False)
    )

    return results


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        path = sys.argv[1]

        try:
            if path.endswith(".mp4"):
                result = audit_episode(path)
            elif path.endswith((".png", ".jpg", ".jpeg")):
                result = audit_thumbnail(path)
            elif os.path.isdir(path):
                result = full_episode_audit(path)
            else:
                print(f"Unknown file type: {path}")
                sys.exit(1)

            print(json.dumps(result, indent=2))

        except Exception as e:
            print(f"AUDIT FAILED: {e}")
            sys.exit(1)
    else:
        print("Usage: python -m src.utils.audit <video.mp4|thumbnail.png|episode_dir>")

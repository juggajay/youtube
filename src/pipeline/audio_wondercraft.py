"""
Wondercraft Audio Engine - Creates natural podcast audio using Wondercraft API.

Wondercraft specializes in podcast generation with natural-sounding conversations.
Uses the convo-mode endpoint for 2-host discussions.
"""

import json
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)

WONDERCRAFT_API_URL = "https://api.wondercraft.ai/v1"


def generate_audio_wondercraft(
    script: dict,
    output_dir: str,
    mock: bool = False,
) -> dict:
    """
    Generate podcast audio using Wondercraft API.

    Args:
        script: episode_script.json structure with dialogue
        output_dir: Directory to save audio files
        mock: If True, skip API call and generate mock data

    Returns:
        audio_manifest.json structure
    """
    config = get_config()
    api_key = config.get("env", {}).get("wondercraft_api_key")
    voice_config = config.get("wondercraft_voices", {})

    episode_date = script["episode_date"]
    dialogue = script["dialogue"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if mock or not api_key:
        logger.info("Using mock mode for Wondercraft")
        return _generate_mock_manifest(dialogue, output_path, episode_date)

    # Get voice IDs from config
    alec_voice_id = voice_config.get("alec", {}).get("voice_id")
    melody_voice_id = voice_config.get("melody", {}).get("voice_id")

    if not alec_voice_id or not melody_voice_id:
        logger.error("Wondercraft voice IDs not configured. Add wondercraft_voices to config.")
        return _generate_mock_manifest(dialogue, output_path, episode_date)

    # Build script segments for Wondercraft API
    segments = []
    for line in dialogue:
        if line.get("chunk_type") != "spoken":
            continue

        speaker = line["speaker"]
        voice_id = alec_voice_id if speaker == "Alec" else melody_voice_id

        # Clean text (remove narrative tags like [serious tone])
        text = _clean_text(line["text"])

        segments.append({
            "text": text,
            "voice_id": voice_id,
        })

    # Submit job to Wondercraft
    logger.info(f"Submitting {len(segments)} segments to Wondercraft API...")

    job_id = _submit_wondercraft_job(api_key, segments)

    if not job_id:
        logger.error("Failed to submit Wondercraft job")
        return _generate_mock_manifest(dialogue, output_path, episode_date)

    # Poll for completion
    logger.info(f"Wondercraft job submitted: {job_id}")
    logger.info("Waiting for audio generation (expect ~1 min per minute of audio)...")

    result = _poll_for_completion(api_key, job_id, timeout_minutes=15)

    if not result or not result.get("url"):
        logger.error("Wondercraft job failed or timed out")
        return _generate_mock_manifest(dialogue, output_path, episode_date)

    # Download audio file
    audio_url = result["url"]
    audio_file = output_path / f"episode_{episode_date}.mp3"

    logger.info(f"Downloading audio from Wondercraft...")
    _download_file(audio_url, audio_file)

    # Get duration (estimate from file size or use ffprobe)
    duration_seconds = _get_audio_duration(audio_file)

    # Generate timestamps (estimated since Wondercraft doesn't provide them)
    timestamps = _estimate_timestamps(dialogue, duration_seconds)

    manifest = {
        "episode_date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "audio_file": str(audio_file),
        "duration_seconds": duration_seconds,
        "format": "mp3",
        "line_timestamps": timestamps,
        "sources": {
            "tts_provider": "wondercraft",
            "job_id": job_id,
        },
    }

    # Save manifest
    manifest_path = output_path / "audio_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Audio generated: {audio_file} ({duration_seconds:.1f}s)")

    return manifest


def _submit_wondercraft_job(api_key: str, segments: List[dict]) -> Optional[str]:
    """Submit a job to Wondercraft convo-mode API."""
    headers = {
        "X-API-KEY": api_key,
        "Content-Type": "application/json",
    }

    payload = {
        "script": segments,
    }

    try:
        response = requests.post(
            f"{WONDERCRAFT_API_URL}/podcast/convo-mode/user-scripted",
            headers=headers,
            json=payload,
            timeout=60,
        )
        response.raise_for_status()

        data = response.json()
        return data.get("job_id")

    except requests.RequestException as e:
        logger.error(f"Wondercraft API error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return None


def _poll_for_completion(
    api_key: str,
    job_id: str,
    timeout_minutes: int = 15,
    poll_interval: int = 10,
) -> Optional[dict]:
    """Poll Wondercraft API for job completion."""
    headers = {
        "X-API-KEY": api_key,
    }

    deadline = time.time() + (timeout_minutes * 60)

    while time.time() < deadline:
        try:
            response = requests.get(
                f"{WONDERCRAFT_API_URL}/podcast/{job_id}",
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()

            if data.get("error"):
                logger.error(f"Wondercraft job error: {data}")
                return None

            if data.get("finished"):
                logger.info("Wondercraft job completed!")
                return data

            logger.info("Still processing... waiting")
            time.sleep(poll_interval)

        except requests.RequestException as e:
            logger.warning(f"Poll request failed: {e}")
            time.sleep(poll_interval)

    logger.error("Wondercraft job timed out")
    return None


def _download_file(url: str, output_path: Path) -> bool:
    """Download a file from URL."""
    try:
        response = requests.get(url, timeout=120, stream=True)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        return True

    except requests.RequestException as e:
        logger.error(f"Download failed: {e}")
        return False


def _get_audio_duration(audio_file: Path) -> float:
    """Get audio duration using ffprobe or estimate from file size."""
    try:
        import subprocess
        result = subprocess.run(
            [
                "ffprobe", "-v", "quiet", "-show_entries",
                "format=duration", "-of", "csv=p=0", str(audio_file)
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip())
    except Exception:
        pass

    # Estimate: ~1MB per minute for 128kbps MP3
    file_size = audio_file.stat().st_size
    return (file_size / 1_000_000) * 60


def _estimate_timestamps(dialogue: List[dict], total_duration: float) -> List[dict]:
    """Estimate timestamps based on word count distribution."""
    spoken_lines = [d for d in dialogue if d.get("chunk_type") == "spoken"]

    if not spoken_lines:
        return []

    # Calculate total words
    total_words = sum(len(d["text"].split()) for d in spoken_lines)

    if total_words == 0:
        return []

    # Distribute time proportionally
    timestamps = []
    current_ms = 0

    for line in spoken_lines:
        word_count = len(line["text"].split())
        duration_ms = int((word_count / total_words) * total_duration * 1000)

        timestamps.append({
            "index": line["index"],
            "speaker": line["speaker"],
            "start_ms": current_ms,
            "end_ms": current_ms + duration_ms,
        })

        current_ms += duration_ms

    return timestamps


def _clean_text(text: str) -> str:
    """Remove narrative tags from text."""
    import re
    # Remove tags like [serious tone], [urgent], but keep content
    text = re.sub(r'\[(?!pause)[^\]]+\]', '', text)
    # Clean up extra whitespace
    text = ' '.join(text.split())
    return text


def _generate_mock_manifest(
    dialogue: List[dict],
    output_path: Path,
    episode_date: str,
) -> dict:
    """Generate mock manifest for testing."""
    audio_file = output_path / f"episode_{episode_date}.mp3"
    audio_file.touch()

    # Estimate duration: 3 seconds per line
    duration = len(dialogue) * 3.0

    timestamps = []
    current_ms = 0
    for line in dialogue:
        duration_ms = 3000
        timestamps.append({
            "index": line["index"],
            "speaker": line["speaker"],
            "start_ms": current_ms,
            "end_ms": current_ms + duration_ms,
        })
        current_ms += duration_ms

    return {
        "episode_date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "audio_file": str(audio_file),
        "duration_seconds": duration,
        "format": "mp3",
        "line_timestamps": timestamps,
        "sources": {
            "tts_provider": "mock",
        },
    }

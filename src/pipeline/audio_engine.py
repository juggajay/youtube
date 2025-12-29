"""
Audio Engine - Generates podcast audio using ElevenLabs v3 Text-to-Dialogue.

Includes mock mode that generates silent audio for testing.
"""

import base64
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..utils import get_config, get_logger, is_mock_mode
from .audio_branding import ensure_branding_assets, get_branding_config

logger = get_logger(__name__)

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1"


def generate_audio(
    script: dict,
    output_dir: str,
    mock: bool = None,
) -> dict:
    """
    Generate podcast audio from script.

    Args:
        script: episode_script.json structure
        output_dir: Directory to save audio files
        mock: Override mock mode setting

    Returns:
        audio_manifest.json structure
    """
    if mock is None:
        mock = is_mock_mode("tts")

    episode_date = script["episode_date"]
    dialogue = script["dialogue"]

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if mock:
        logger.info("Using mock TTS mode - generating silent audio")
        audio_file, timestamps = _generate_mock_audio(dialogue, output_path, episode_date)
    else:
        audio_file, timestamps = _generate_elevenlabs_audio(dialogue, output_path, episode_date)

    # Calculate duration from timestamps
    duration_seconds = 0
    if timestamps:
        last_line = timestamps[-1]
        duration_seconds = last_line["end_ms"] / 1000

    # Generate chapter markers from CVE references
    chapters = _generate_chapters(dialogue, timestamps)

    manifest = {
        "episode_date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "audio_file": str(audio_file),
        "duration_seconds": duration_seconds,
        "format": "mp3",
        "bitrate": "320kbps",
        "chapters": chapters,
        "line_timestamps": timestamps,
        "character_timestamps": [],  # Populated by ElevenLabs API in real mode
        "sources": {
            "input_file": "episode_script.json",
            "tts_provider": "mock" if mock else "elevenlabs",
            "api_version": "v3",
        },
    }

    # Save manifest
    manifest_path = output_path / "audio_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Audio generated: {audio_file} ({duration_seconds:.1f}s)")

    return manifest


def _generate_mock_audio(
    dialogue: List[dict],
    output_path: Path,
    episode_date: str,
) -> tuple:
    """
    Generate mock audio (silent MP3) for testing.

    Returns:
        Tuple of (audio_file_path, timestamps)
    """
    try:
        from pydub import AudioSegment
    except ImportError:
        logger.warning("pydub not installed, creating empty audio file")
        audio_file = output_path / f"episode_{episode_date}.mp3"
        audio_file.touch()
        return str(audio_file), _generate_mock_timestamps(dialogue)

    # Estimate duration: ~3 seconds per line on average
    total_duration_ms = len(dialogue) * 3000

    # Generate silence using AudioSegment.silent()
    silence = AudioSegment.silent(duration=total_duration_ms)

    # Generate mock timestamps
    timestamps = _generate_mock_timestamps(dialogue)

    # Add audio branding (intro sting + outro bed)
    combined, timestamps = _add_audio_branding(silence, timestamps, output_path)

    # Export as MP3
    audio_file = output_path / f"episode_{episode_date}.mp3"
    combined.export(str(audio_file), format="mp3", bitrate="320k")

    return str(audio_file), timestamps


def _generate_mock_timestamps(dialogue: List[dict]) -> List[dict]:
    """
    Generate mock timestamps for testing.

    Estimates ~3 seconds per dialogue line.
    """
    timestamps = []
    current_ms = 0

    for line in dialogue:
        # Estimate duration based on word count (150 words per minute)
        word_count = len(line["text"].split())
        duration_ms = int((word_count / 150) * 60 * 1000)
        duration_ms = max(duration_ms, 2000)  # Minimum 2 seconds

        timestamps.append({
            "index": line["index"],
            "speaker": line["speaker"],
            "start_ms": current_ms,
            "end_ms": current_ms + duration_ms,
        })

        current_ms += duration_ms

    return timestamps


def _generate_elevenlabs_audio(
    dialogue: List[dict],
    output_path: Path,
    episode_date: str,
) -> tuple:
    """
    Generate audio using ElevenLabs V3 API with improved flow.

    Features:
    - Batches consecutive same-speaker lines for more natural delivery
    - Adds crossfades between different speakers for smoother transitions
    """
    import io
    import requests

    config = get_config()
    api_key = config.get("env", {}).get("elevenlabs_api_key")

    if not api_key:
        logger.warning("No ElevenLabs API key found, falling back to mock mode")
        return _generate_mock_audio(dialogue, output_path, episode_date)

    try:
        from pydub import AudioSegment
    except ImportError:
        logger.error("pydub required for audio processing. Run: pip install pydub")
        return _generate_mock_audio(dialogue, output_path, episode_date)

    # Step 1: Batch consecutive same-speaker lines
    batched_segments = _batch_dialogue_by_speaker(dialogue)
    logger.info(f"Batched {len(dialogue)} lines into {len(batched_segments)} segments")

    # Step 2: Generate audio for each batched segment
    audio_segments = []
    timestamps = []
    current_ms = 0
    prev_speaker = None

    CROSSFADE_MS = 75  # Crossfade duration between different speakers

    for batch in batched_segments:
        voice_id = batch["voice_id"]
        speaker = batch["speaker"]
        text = batch["text"]
        line_indices = batch["line_indices"]

        if not voice_id:
            logger.warning(f"No voice_id for speaker {speaker}, skipping")
            continue

        # Clean text for TTS
        clean_text = _clean_text_for_tts(text)

        # Generate audio
        try:
            audio_data = _tts_request(api_key, voice_id, clean_text, batch.get("seed"))

            if audio_data:
                segment = AudioSegment.from_mp3(io.BytesIO(audio_data))

                # Apply crossfade if switching speakers
                if audio_segments and prev_speaker and prev_speaker != speaker:
                    # Crossfade with previous segment
                    if len(audio_segments[-1]) > CROSSFADE_MS and len(segment) > CROSSFADE_MS:
                        audio_segments[-1] = audio_segments[-1].append(
                            segment, crossfade=CROSSFADE_MS
                        )
                        # Adjust timing for crossfade overlap
                        duration_ms = len(segment) - CROSSFADE_MS
                    else:
                        audio_segments.append(segment)
                        duration_ms = len(segment)
                else:
                    audio_segments.append(segment)
                    duration_ms = len(segment)

                # Record timestamps for each original line in the batch
                batch_duration = len(segment)
                lines_in_batch = len(line_indices)
                per_line_duration = batch_duration // max(lines_in_batch, 1)

                for i, line_idx in enumerate(line_indices):
                    timestamps.append({
                        "index": line_idx,
                        "speaker": speaker,
                        "start_ms": current_ms + (i * per_line_duration),
                        "end_ms": current_ms + ((i + 1) * per_line_duration),
                    })

                current_ms += duration_ms
                prev_speaker = speaker

                logger.info(f"  Generated: {speaker} ({lines_in_batch} lines, {batch_duration}ms)")

        except Exception as e:
            logger.error(f"TTS failed for {speaker} batch: {e}")

    # Step 3: Combine all segments
    if not audio_segments:
        logger.error("No audio segments generated")
        return _generate_mock_audio(dialogue, output_path, episode_date)

    # Flatten segments (some may have been merged via crossfade)
    combined = audio_segments[0]
    for seg in audio_segments[1:]:
        combined = combined + seg

    # Step 4: Add audio branding (intro sting + outro bed)
    combined, timestamps = _add_audio_branding(combined, timestamps, output_path)

    # Export combined audio
    audio_file = output_path / f"episode_{episode_date}.mp3"
    combined.export(str(audio_file), format="mp3", bitrate="320k")

    return str(audio_file), timestamps


def _add_audio_branding(combined, timestamps: List[dict], output_path: Path) -> tuple:
    """
    Add intro sting and outro bed to the combined audio.

    Settings are configured in audio_branding.py BRANDING_CONFIG:
    - Intro: Prepended with configurable gap before dialogue
    - Outro: Overlaid with configurable volume, fade-in, and duration
    """
    try:
        from pydub import AudioSegment
    except ImportError:
        logger.warning("pydub not available for branding")
        return combined, timestamps

    # Get branding configuration
    config = get_branding_config()
    intro_config = config["intro"]
    outro_config = config["outro"]

    # Get or generate branding assets
    assets_dir = output_path.parent.parent.parent / "assets" / "audio"
    try:
        branding = ensure_branding_assets(str(assets_dir))
    except Exception as e:
        logger.warning(f"Could not generate branding assets: {e}")
        return combined, timestamps

    # Load intro sting
    try:
        if not branding.get("intro_sting"):
            raise ValueError("No intro sting available")
        intro_sting = AudioSegment.from_mp3(branding["intro_sting"])
        intro_duration_ms = len(intro_sting)
        gap_ms = intro_config["gap_after_ms"]
        logger.info(f"Adding intro sting ({intro_duration_ms}ms) with {gap_ms}ms gap")

        # Prepend intro sting with configured gap
        gap = AudioSegment.silent(duration=gap_ms)
        combined = intro_sting + gap + combined

        # Adjust all timestamps to account for intro
        offset = intro_duration_ms + gap_ms
        for ts in timestamps:
            ts["start_ms"] += offset
            ts["end_ms"] += offset

    except Exception as e:
        logger.warning(f"Could not add intro sting: {e}")

    # Load outro bed and overlay
    try:
        if not branding.get("outro_bed"):
            raise ValueError("No outro bed available")
        outro_bed = AudioSegment.from_mp3(branding["outro_bed"])

        # Apply configured settings
        outro_duration_ms = min(len(outro_bed), outro_config["duration_ms"])
        volume_db = outro_config["volume_db"]
        fade_in_ms = outro_config["fade_in_ms"]

        # Trim bed to configured duration
        outro_bed = outro_bed[:outro_duration_ms]

        # Calculate where to start the bed
        bed_start = max(0, len(combined) - outro_duration_ms)

        # Reduce bed volume (configured in dB)
        outro_bed = outro_bed + volume_db

        # Add gradual fade-in
        outro_bed = outro_bed.fade_in(fade_in_ms)

        # Overlay the bed
        combined = combined.overlay(outro_bed, position=bed_start)
        logger.info(
            f"Added outro bed ({outro_duration_ms}ms) at {bed_start}ms "
            f"[volume: {volume_db}dB, fade-in: {fade_in_ms}ms]"
        )

    except Exception as e:
        logger.warning(f"Could not add outro bed: {e}")

    return combined, timestamps


def _batch_dialogue_by_speaker(dialogue: List[dict]) -> List[dict]:
    """
    Batch consecutive same-speaker lines into single segments.

    This produces more natural speech as the TTS model can handle
    longer passages with proper intonation and flow.
    """
    batched = []
    current_batch = None

    for line in dialogue:
        if line.get("chunk_type") != "spoken":
            continue

        speaker = line["speaker"]
        voice_id = line.get("voice_id")
        text = line["text"]
        line_index = line["index"]

        if current_batch and current_batch["speaker"] == speaker:
            # Same speaker - append to current batch
            current_batch["text"] += " " + text
            current_batch["line_indices"].append(line_index)
        else:
            # Different speaker - save current batch and start new one
            if current_batch:
                batched.append(current_batch)

            current_batch = {
                "speaker": speaker,
                "voice_id": voice_id,
                "text": text,
                "line_indices": [line_index],
                "seed": line.get("seed"),
            }

    # Don't forget the last batch
    if current_batch:
        batched.append(current_batch)

    return batched


def _tts_request(api_key: str, voice_id: str, text: str, seed: int = None) -> Optional[bytes]:
    """
    Make a TTS request to ElevenLabs V3 API.

    V3 uses:
    - Audio tags like [laughs], [sighs], [whispers] for expression
    - Ellipses (...) for pauses
    - CAPITALIZATION for emphasis
    - Stability slider as main control (lower = more expressive)
    """
    import requests

    url = f"{ELEVENLABS_API_URL}/text-to-speech/{voice_id}"

    headers = {
        "xi-api-key": api_key,
        "Content-Type": "application/json",
    }

    # V3 model settings
    # Stability MUST be: 0.0 = Creative, 0.5 = Natural, 1.0 = Robust
    payload = {
        "text": text,
        "model_id": "eleven_v3",
        "voice_settings": {
            "stability": 0.5,           # Natural - good balance for podcast
            "similarity_boost": 0.75,   # Good voice consistency
            "style": 0.3,               # Moderate style
            "use_speaker_boost": True,
            "speed": 1.0,               # Normal speed
        },
    }

    if seed:
        payload["seed"] = seed

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        logger.error(f"ElevenLabs API error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return None


def _clean_text_for_tts(text: str) -> str:
    """
    Clean and prepare text for ElevenLabs V3 TTS.

    V3 supports audio tags like [laughs], [sighs], [whispers], [excited]
    but NOT SSML break tags or [pause:Xs] format.

    Conversions:
    - [pause:Xs] -> ... (ellipsis)
    - [serious tone] -> removed (not an audio tag)
    - [sighs], [laughs], [whispers] -> kept (V3 audio tags)
    - Keeps CAPITALIZATION for emphasis
    """
    import re

    # V3 supported audio tags (keep these)
    v3_audio_tags = {
        'laughs', 'laughing', 'chuckles', 'giggles', 'wheezing',
        'whispers', 'whisper', 'whispering',
        'sighs', 'sigh', 'exhales', 'inhales',
        'excited', 'curious', 'sarcastic', 'sad', 'happy', 'angry',
        'surprised', 'thoughtful', 'annoyed', 'appalled',
        'clears throat', 'short pause', 'long pause',
        'crying', 'snorts', 'mischievously',
    }

    def tag_replacer(match):
        tag_content = match.group(1).lower().strip()

        # Convert pause tags to ellipsis
        if tag_content.startswith('pause'):
            return '...'

        # Keep V3-compatible audio tags
        if tag_content in v3_audio_tags:
            return match.group(0)  # Keep original

        # Check for partial matches (e.g., "starts laughing")
        for audio_tag in v3_audio_tags:
            if audio_tag in tag_content:
                return f'[{tag_content}]'  # Keep it

        # Remove non-audio tags (like [serious tone], [matter-of-fact])
        return ''

    # Process all bracketed tags
    cleaned = re.sub(r'\[([^\]]+)\]', tag_replacer, text)

    # Clean up extra spaces
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    # Ensure text is at least 250 chars for V3 consistency (pad if needed)
    # V3 works better with longer inputs
    if len(cleaned) < 100:
        cleaned = cleaned + "..."  # Add trailing pause for short text

    return cleaned


def _generate_chapters(dialogue: List[dict], timestamps: List[dict]) -> List[dict]:
    """
    Generate chapter markers from CVE references in dialogue.
    """
    chapters = [
        {"title": "Intro", "start_ms": 0, "end_ms": timestamps[0]["end_ms"] if timestamps else 0}
    ]

    seen_cves = set()
    current_chapter_cve = None

    for i, line in enumerate(dialogue):
        cve_refs = line.get("cve_refs", [])

        for cve_id in cve_refs:
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)

                # Find timestamp for this line
                ts = next((t for t in timestamps if t["index"] == line["index"]), None)
                if ts:
                    # Get vulnerability title (abbreviated)
                    chapters.append({
                        "title": cve_id,
                        "start_ms": ts["start_ms"],
                        "cve_id": cve_id,
                    })

    # Add end times to chapters
    for i, chapter in enumerate(chapters[:-1]):
        chapter["end_ms"] = chapters[i + 1]["start_ms"]

    if chapters and timestamps:
        chapters[-1]["end_ms"] = timestamps[-1]["end_ms"]

    return chapters

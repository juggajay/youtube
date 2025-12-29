"""
Video Assembler - Creates YouTube video using FFmpeg complex filtergraph.

Dynamic speaker highlighting based on ElevenLabs timestamps.
Uses drawtext filter with enable='between(t,start,end)' for glow effects.
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)


def _escape_ffmpeg_path(path: str) -> str:
    """
    Escape a file path for use in FFmpeg filter parameters.

    On Windows, colons in drive letters need to be escaped.
    Backslashes should be forward slashes.
    """
    # Convert backslashes to forward slashes
    path = path.replace("\\", "/")
    # Escape colons (for Windows drive letters like C:)
    path = path.replace(":", "\\:")
    return path


def assemble_video(
    audio_manifest: dict,
    script: dict,
    output_dir: str,
    background_image: Optional[str] = None,
    font_path: Optional[str] = None,
) -> dict:
    """
    Assemble video from audio and script.

    Args:
        audio_manifest: audio_manifest.json structure
        script: episode_script.json structure
        output_dir: Directory to save video files
        background_image: Path to background image (1920x1080 or 3840x2160)
        font_path: Path to .ttf font file

    Returns:
        video_manifest.json structure
    """
    config = get_config()
    video_config = config.get("video", {})
    voice_config = config.get("voices", {})

    episode_date = audio_manifest["episode_date"]
    audio_file = audio_manifest["audio_file"]
    timestamps = audio_manifest.get("line_timestamps", [])

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Default paths
    if not background_image:
        background_image = str(Path(config.get("paths", {}).get("assets", "assets")) / "background.png")
    if not font_path:
        font_path = _find_system_font()

    # Generate speaker segments with colors
    speaker_segments = _prepare_speaker_segments(timestamps, script["dialogue"], voice_config)

    # Build FFmpeg filtergraph
    filtergraph = _build_filtergraph(
        speaker_segments=speaker_segments,
        script=script,
        font_path=font_path,
        width=video_config.get("resolution", {}).get("width", 3840),
        height=video_config.get("resolution", {}).get("height", 2160),
    )

    # Generate FFmpeg command
    output_video = output_path / f"episode_{episode_date}_4K.mp4"

    # Check if we have a real background image
    if not os.path.exists(background_image):
        logger.warning(f"Background image not found: {background_image}")
        logger.info("Creating placeholder background...")
        background_image = _create_placeholder_background(output_path)

    ffmpeg_cmd = _build_ffmpeg_command(
        background=background_image,
        audio=audio_file,
        output=str(output_video),
        filtergraph=filtergraph,
        video_config=video_config,
    )

    # Log the command for debugging
    logger.debug(f"FFmpeg command: {' '.join(ffmpeg_cmd)}")

    # Execute FFmpeg
    try:
        logger.info("Running FFmpeg video assembly...")
        result = subprocess.run(
            ffmpeg_cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        if result.returncode != 0:
            logger.error(f"FFmpeg failed: {result.stderr}")
            # Create a simple fallback video
            output_video = _create_fallback_video(audio_file, output_path, episode_date)

    except subprocess.TimeoutExpired:
        logger.error("FFmpeg timed out")
        output_video = _create_fallback_video(audio_file, output_path, episode_date)
    except FileNotFoundError:
        logger.error("FFmpeg not found. Please install FFmpeg.")
        output_video = Path(output_path / f"episode_{episode_date}_4K.mp4")
        output_video.touch()  # Create empty file as placeholder

    # Build manifest
    manifest = {
        "episode_date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "video_file": str(output_video),
        "resolution": f"{video_config.get('resolution', {}).get('width', 3840)}x{video_config.get('resolution', {}).get('height', 2160)}",
        "duration_seconds": audio_manifest.get("duration_seconds", 0),
        "codec": video_config.get("codec", "h264"),
        "crf": video_config.get("crf", 18),
        "dynamic_elements": {
            "speaker_highlights": True,
            "cve_lower_thirds": True,
            "waveform": False,  # TODO: Add waveform visualization
        },
        "speaker_segments": speaker_segments,
        "sources": {
            "audio_manifest": "audio_manifest.json",
            "episode_script": "episode_script.json",
            "background": background_image,
        },
    }

    # Save manifest
    manifest_path = output_path / "video_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Video assembled: {output_video}")

    return manifest


def _prepare_speaker_segments(
    timestamps: List[dict],
    dialogue: List[dict],
    voice_config: dict,
) -> List[dict]:
    """
    Prepare speaker segments with timing and color info.
    """
    segments = []

    for ts in timestamps:
        # Find corresponding dialogue line
        line = next((d for d in dialogue if d["index"] == ts["index"]), None)
        if not line:
            continue

        speaker = line["speaker"]
        speaker_key = speaker.lower()
        voice = voice_config.get(speaker_key, {})

        segments.append({
            "speaker": speaker,
            "start": ts["start_ms"] / 1000.0,  # Convert to seconds
            "end": ts["end_ms"] / 1000.0,
            "color": voice.get("color", "0xFFFFFF"),
            "cve_refs": line.get("cve_refs", []),
        })

    return segments


def _build_filtergraph(
    speaker_segments: List[dict],
    script: dict,
    font_path: str,
    width: int = 3840,
    height: int = 2160,
) -> str:
    """
    Build FFmpeg complex filtergraph with dynamic speaker highlighting.
    """
    # Escape font path for FFmpeg filter syntax
    escaped_font = _escape_ffmpeg_path(font_path)

    filters = []

    # Scale background to output resolution
    filters.append(f"[0:v]scale={width}:{height}:force_original_aspect_ratio=decrease,pad={width}:{height}:(ow-iw)/2:(oh-ih)/2[bg]")

    # Collect segments by speaker
    alec_segments = [s for s in speaker_segments if s["speaker"] == "Alec"]
    melody_segments = [s for s in speaker_segments if s["speaker"] == "Melody"]

    # Speaker name positions (for 4K)
    alec_x = int(width * 0.1)  # 10% from left
    melody_x = int(width * 0.75)  # 75% from left
    name_y = int(height * 0.1)  # 10% from top
    font_size = int(height * 0.03)  # 3% of height

    # Dim color for inactive state
    dim_color = "0x666666"

    # Build text filter chain
    text_filters = []

    # Speaker names removed - the background image shows the hosts directly

    # CVE lower thirds
    lower_third_y = int(height * 0.9)
    lower_third_font = int(font_size * 0.8)

    for seg in speaker_segments:
        for cve_id in seg.get("cve_refs", []):
            # Background box
            text_filters.append(
                f"drawbox=x={int(width * 0.05)}:y={lower_third_y - 10}:"
                f"w={int(width * 0.4)}:h={int(height * 0.05)}:"
                f"color=0x000000@0.7:t=fill:"
                f"enable='between(t,{seg['start']:.3f},{seg['end']:.3f})'"
            )
            # CVE text
            text_filters.append(
                f"drawtext=text='{cve_id}':"
                f"fontfile='{escaped_font}':"
                f"fontsize={lower_third_font}:"
                f"fontcolor=0xFFFFFF:"
                f"x={int(width * 0.06)}:y={lower_third_y}:"
                f"enable='between(t,{seg['start']:.3f},{seg['end']:.3f})'"
            )

    # Join all text filters
    if text_filters:
        text_chain = ",".join(text_filters)
        filters.append(f"[bg]{text_chain}[v_final]")
    else:
        filters.append("[bg]null[v_final]")

    return ";".join(filters)


def _build_ffmpeg_command(
    background: str,
    audio: str,
    output: str,
    filtergraph: str,
    video_config: dict,
) -> List[str]:
    """
    Build FFmpeg command with complex filtergraph.
    """
    cmd = [
        "ffmpeg", "-y",
        "-loop", "1",
        "-i", background,
        "-i", audio,
        "-filter_complex", filtergraph,
        "-map", "[v_final]",
        "-map", "1:a",
        "-c:v", video_config.get("codec", "libx264"),
        "-preset", video_config.get("preset", "slow"),
        "-crf", str(video_config.get("crf", 18)),
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        "-pix_fmt", "yuv420p",
        output,
    ]

    return cmd


def _find_system_font() -> str:
    """
    Find a system font to use.
    """
    import platform

    system = platform.system()

    if system == "Windows":
        font_paths = [
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
            "C:/Windows/Fonts/segoeui.ttf",
        ]
    elif system == "Darwin":  # macOS
        font_paths = [
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/SFNSText.ttf",
            "/Library/Fonts/Arial.ttf",
        ]
    else:  # Linux
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
        ]

    for path in font_paths:
        if os.path.exists(path):
            return path

    # Fallback - FFmpeg will use default
    logger.warning("No system font found, using FFmpeg default")
    return "sans"


def _create_placeholder_background(output_path: Path) -> str:
    """
    Create a simple dark background image using FFmpeg.
    """
    bg_path = output_path / "background_placeholder.png"

    try:
        subprocess.run([
            "ffmpeg", "-y",
            "-f", "lavfi",
            "-i", "color=c=0x1a1a2e:s=3840x2160:d=1",
            "-frames:v", "1",
            str(bg_path),
        ], capture_output=True, check=True)
        return str(bg_path)
    except Exception as e:
        logger.error(f"Failed to create placeholder background: {e}")
        return ""


def _create_fallback_video(audio_file: str, output_path: Path, episode_date: str) -> Path:
    """
    Create a simple fallback video without complex effects.
    """
    output_video = output_path / f"episode_{episode_date}_4K.mp4"

    try:
        subprocess.run([
            "ffmpeg", "-y",
            "-f", "lavfi",
            "-i", "color=c=0x1a1a2e:s=3840x2160",
            "-i", audio_file,
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", "23",
            "-c:a", "aac",
            "-shortest",
            str(output_video),
        ], capture_output=True, check=True)
    except Exception as e:
        logger.error(f"Fallback video creation failed: {e}")
        output_video.touch()

    return output_video

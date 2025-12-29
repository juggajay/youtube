"""
Audio Branding - Provides intro sting and outro bed for podcast.

Uses royalty-free audio from Mixkit (https://mixkit.co).

AUDIO ASSETS:
=============
Intro Sting: assets/audio/intro_sting.mp3
  - Source: Mixkit "Musical news presentation intro"
  - Duration: ~7 seconds
  - Style: News/broadcast presentation sound
  - License: Mixkit Free License (https://mixkit.co/license/#sfxFree)

Outro Bed: assets/audio/outro_bed.mp3
  - Source: Mixkit "Pop 09"
  - Duration: 68 seconds (trimmed to 15 seconds in playback)
  - Style: Electronica, Positive, Futuristic
  - License: Mixkit Free License (https://mixkit.co/license/#musicFree)

BRANDING SETTINGS (configured in audio_engine.py):
==================================================
- Intro: Prepended with 300ms gap before dialogue
- Outro:
  - Volume: -18dB (so it doesn't compete with speech)
  - Fade-in: 5 seconds (gradual rise as dialogue ends)
  - Duration: 15 seconds (overlaid on final 15 seconds of episode)
"""

from pathlib import Path

from ..utils import get_logger

logger = get_logger(__name__)

# Branding configuration
BRANDING_CONFIG = {
    "intro": {
        "filename": "intro_sting.mp3",
        "gap_after_ms": 300,  # Gap between intro and dialogue
    },
    "outro": {
        "filename": "outro_bed.mp3",
        "volume_db": -18,      # Volume reduction in dB
        "fade_in_ms": 5000,    # Fade-in duration in milliseconds
        "duration_ms": 15000,  # Max duration to use from outro file
    },
}


def get_branding_config() -> dict:
    """Return the branding configuration settings."""
    return BRANDING_CONFIG


def ensure_branding_assets(assets_dir: str, force_regenerate: bool = False) -> dict:
    """
    Ensure branding audio assets exist.

    Args:
        assets_dir: Directory to find assets
        force_regenerate: Ignored (assets are pre-downloaded)

    Returns:
        Dict with paths to intro_sting and outro_bed
    """
    assets_path = Path(assets_dir)

    intro_path = assets_path / BRANDING_CONFIG["intro"]["filename"]
    outro_path = assets_path / BRANDING_CONFIG["outro"]["filename"]

    result = {}

    if intro_path.exists():
        result["intro_sting"] = str(intro_path)
        logger.info(f"Using intro sting: {intro_path}")
    else:
        logger.warning(f"Intro sting not found at {intro_path}")
        result["intro_sting"] = None

    if outro_path.exists():
        result["outro_bed"] = str(outro_path)
        logger.info(f"Using outro bed: {outro_path}")
    else:
        logger.warning(f"Outro bed not found at {outro_path}")
        result["outro_bed"] = None

    return result

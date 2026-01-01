"""
Configuration management for the podcast pipeline.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv

# Global config instance
_config: Optional[dict] = None


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load configuration from YAML file and environment variables.

    Args:
        config_path: Path to config.yaml. Defaults to config/config.yaml

    Returns:
        Merged configuration dictionary
    """
    global _config

    # Load .env file
    load_dotenv()

    # Default config path
    if config_path is None:
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "config" / "config.yaml"

    # Load YAML config
    with open(config_path, "r") as f:
        _config = yaml.safe_load(f)

    # Inject environment variables
    _config["env"] = {
        "elevenlabs_api_key": os.getenv("ELEVENLABS_API_KEY"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "gemini_api_key": os.getenv("GEMINI_API_KEY"),
        "nvd_api_key": os.getenv("NVD_API_KEY"),
        "airtable_api_key": os.getenv("AIRTABLE_API_KEY"),
        "airtable_base_id": os.getenv("AIRTABLE_BASE_ID"),
        "youtube_client_id": os.getenv("YOUTUBE_CLIENT_ID"),
        "youtube_client_secret": os.getenv("YOUTUBE_CLIENT_SECRET"),
        "youtube_refresh_token": os.getenv("YOUTUBE_REFRESH_TOKEN"),
        "blog_api_url": os.getenv("BLOG_API_URL"),
        "blog_api_key": os.getenv("BLOG_API_KEY"),
        "buffer_api_key": os.getenv("BUFFER_API_KEY"),
    }

    return _config


def get_config() -> dict:
    """
    Get the current configuration.

    Returns:
        Configuration dictionary

    Raises:
        RuntimeError: If config hasn't been loaded yet
    """
    global _config

    if _config is None:
        _config = load_config()

    return _config


def get_voice_config(speaker: str) -> dict:
    """
    Get voice configuration for a speaker.

    Args:
        speaker: "alex" or "morgan"

    Returns:
        Voice configuration dict with voice_id, seed, color, etc.
    """
    config = get_config()
    return config["voices"].get(speaker.lower(), {})


def is_mock_mode(component: str = None) -> bool:
    """
    Check if mock mode is enabled.

    Args:
        component: Specific component to check ("llm", "tts", "thumbnail")
                   If None, checks if mock mode is enabled at all.

    Returns:
        True if mock mode is enabled for the component
    """
    config = get_config()
    mock_config = config.get("mock_mode", {})

    if not mock_config.get("enabled", False):
        return False

    if component is None:
        return True

    return mock_config.get(component, False)

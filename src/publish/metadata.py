"""
Metadata Generator - Creates SEO-optimized YouTube metadata using LLM.

Generates:
- Click-optimized titles (5 options with best marked)
- Engaging descriptions with CVE details
- Targeted tags for discoverability
- Chapter markers from audio timestamps

Uses the metadata_prompt.txt system prompt for consistent SEO strategy.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)

PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "metadata_prompt.txt"


def generate_youtube_metadata(
    daily_brief: dict,
    stories: List[dict] = None,
    mock: bool = False,
) -> dict:
    """
    Generate SEO-optimized YouTube metadata using LLM.

    Args:
        daily_brief: The daily_brief_packet.json data
        stories: Optional list of news stories
        mock: Use mock data instead of LLM

    Returns:
        Dict with titles, primary_title, description, tags
    """
    if mock:
        return _generate_mock_metadata(daily_brief)

    # Load system prompt
    if not PROMPT_PATH.exists():
        logger.error(f"Metadata prompt not found at {PROMPT_PATH}")
        return _generate_mock_metadata(daily_brief)

    with open(PROMPT_PATH, "r") as f:
        system_prompt = f.read()

    # Prepare input data for LLM
    input_data = {
        "vulnerabilities": daily_brief.get("vulnerabilities", []),
        "filter_stats": daily_brief.get("filter_stats", {}),
        "top_stories": stories or [],
    }

    # Call LLM
    metadata = _call_llm_for_metadata(system_prompt, input_data)

    if not metadata:
        logger.warning("LLM metadata generation failed, using mock")
        return _generate_mock_metadata(daily_brief)

    # Add host branding if missing
    if "Alex" not in metadata.get("description", "") and "Morgan" not in metadata.get("description", ""):
        metadata["description"] += "\n\nHosted by AI Analysts Alex & Morgan."

    return metadata


def _call_llm_for_metadata(system_prompt: str, input_data: dict) -> Optional[dict]:
    """
    Call Anthropic Claude to generate metadata.
    """
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed. Run: pip install anthropic")
        return None

    config = get_config()
    api_key = config.get("env", {}).get("anthropic_api_key")

    if not api_key:
        logger.warning("No Anthropic API key found")
        return None

    try:
        client = anthropic.Anthropic(api_key=api_key)

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": json.dumps(input_data, indent=2)}
            ]
        )

        response_text = message.content[0].text

        # Extract JSON from response (handle markdown code blocks)
        json_text = response_text
        if "```json" in json_text:
            json_text = json_text.split("```json")[1].split("```")[0]
        elif "```" in json_text:
            json_text = json_text.split("```")[1].split("```")[0]

        metadata = json.loads(json_text.strip())

        logger.info(f"Generated metadata: {metadata.get('primary_title', 'No title')}")
        return metadata

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response as JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"LLM API call failed: {e}")
        return None


def _generate_mock_metadata(daily_brief: dict) -> dict:
    """
    Generate mock metadata for testing without LLM.
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stats = daily_brief.get("filter_stats", {})
    critical_count = stats.get("critical_count", 0)
    high_count = stats.get("high_count", 0)

    # Determine title based on content
    if vulns:
        top_vuln = vulns[0]
        vendor = top_vuln.get("vendor", "Unknown")
        cve_id = top_vuln.get("cve_id", "CVE-2025-XXXX")

        if critical_count > 0:
            primary_title = f"{vendor.upper()} CRITICAL: Patch Now ({cve_id})"
        else:
            primary_title = f"{vendor} Security Alert: {cve_id} Explained"
    else:
        primary_title = "Daily Security Brief: What You Need to Know"

    # Build description
    desc_parts = [
        "Your daily cybersecurity intelligence briefing.",
        "",
    ]

    if vulns:
        desc_parts.append(f"Today we cover {len(vulns)} vulnerabilities:")
        for v in vulns[:5]:
            severity = v.get("priority", "HIGH")
            cve_id = v.get("cve_id", "")
            # Build description: prefer title, fall back to vendor+product
            title = v.get("title", "")
            vendor = v.get("vendor", "")
            product = v.get("product", "")

            if title:
                # Truncate long titles
                short_title = title[:60] + "..." if len(title) > 60 else title
                desc_parts.append(f"- [{severity}] {cve_id}: {short_title}")
            elif vendor or product:
                desc_parts.append(f"- [{severity}] {cve_id}: {vendor} {product}".strip())
            else:
                desc_parts.append(f"- [{severity}] {cve_id}")

    desc_parts.extend([
        "",
        "Subscribe for daily security updates.",
        "",
        "Hosted by AI Analysts Alex & Morgan.",
    ])

    # Generate tags
    tags = ["cybersecurity", "infosec", "vulnerability", "CVE", "security news"]
    for v in vulns[:3]:
        if v.get("cve_id"):
            tags.append(v["cve_id"])
        if v.get("vendor"):
            tags.append(v["vendor"].lower())

    return {
        "titles": [
            primary_title,
            f"{critical_count} Critical Vulnerabilities You Must Patch Today",
            "Security Alert: New CVEs Require Immediate Action",
        ],
        "primary_title": primary_title,
        "description": "\n".join(desc_parts),
        "tags": tags[:15],
    }


def append_chapters(description: str, audio_manifest: dict) -> str:
    """
    Append YouTube chapter markers to the description.

    Uses timestamps from audio_manifest to create accurate chapter markers.

    Args:
        description: The existing YouTube description
        audio_manifest: Audio manifest with line_timestamps or chapters

    Returns:
        Description with chapter markers appended
    """
    chapters = audio_manifest.get("chapters", [])

    if not chapters:
        # Try to build chapters from line_timestamps
        chapters = _build_chapters_from_timestamps(audio_manifest)

    if not chapters:
        return description

    description += "\n\n---\nTIMESTAMPS:\n"

    for chapter in chapters:
        start_ms = chapter.get("start_ms", 0)
        title = chapter.get("title", "Segment")

        # Format as MM:SS
        total_seconds = start_ms // 1000
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        timestamp = f"{minutes:02d}:{seconds:02d}"

        description += f"{timestamp} - {title}\n"

    return description


def _build_chapters_from_timestamps(audio_manifest: dict) -> List[dict]:
    """
    Build chapter markers from line timestamps.

    Groups dialogue by topic (CVE mentions) to create logical chapters.
    """
    chapters = []
    line_timestamps = audio_manifest.get("line_timestamps", [])

    if not line_timestamps:
        return chapters

    # Always start with intro
    chapters.append({
        "title": "Intro",
        "start_ms": 0,
    })

    # Group by CVE references (simplified - real impl would use script data)
    seen_topics = set()
    for ts in line_timestamps:
        # This is a simplified version - the full impl would
        # cross-reference with episode_script.json for CVE refs
        if ts.get("cve_id") and ts["cve_id"] not in seen_topics:
            chapters.append({
                "title": ts["cve_id"],
                "start_ms": ts.get("start_ms", 0),
            })
            seen_topics.add(ts["cve_id"])

    return chapters


def format_description_for_youtube(
    metadata: dict,
    audio_manifest: dict = None,
    youtube_links: dict = None,
) -> str:
    """
    Format the final YouTube description with all components.

    Args:
        metadata: The LLM-generated metadata
        audio_manifest: Optional audio manifest for chapters
        youtube_links: Optional dict with subscribe_url, playlist_url, etc.

    Returns:
        Fully formatted YouTube description
    """
    description = metadata.get("description", "")

    # Append chapters if we have audio manifest
    if audio_manifest:
        description = append_chapters(description, audio_manifest)

    # Append standard links
    links = youtube_links or {}
    if links:
        description += "\n\n---\nLINKS:\n"
        if links.get("subscribe_url"):
            description += f"Subscribe: {links['subscribe_url']}\n"
        if links.get("playlist_url"):
            description += f"Full Playlist: {links['playlist_url']}\n"
        if links.get("website_url"):
            description += f"Website: {links['website_url']}\n"

    # Append hashtags (YouTube indexes these)
    tags = metadata.get("tags", [])[:5]
    if tags:
        hashtags = " ".join(f"#{tag.replace(' ', '')}" for tag in tags)
        description += f"\n\n{hashtags}"

    return description


if __name__ == "__main__":
    # Test run
    import sys

    test_path = "output/episodes/2025-01-01/daily_brief_packet.json"
    if Path(test_path).exists():
        with open(test_path) as f:
            data = json.load(f)

        # Test mock mode
        meta = generate_youtube_metadata(data, mock=True)
        print("=" * 60)
        print("MOCK METADATA TEST")
        print("=" * 60)
        print(f"TITLE: {meta['primary_title']}")
        print(f"TAGS: {meta['tags']}")
        print(f"\nDESCRIPTION:\n{meta['description']}")
    else:
        print(f"Test file not found: {test_path}")

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


def _extract_vuln_type(description: str) -> str:
    """Extract the vulnerability type from a CVE description."""
    desc_upper = description.upper()

    # Map patterns to short vulnerability type names
    vuln_patterns = [
        ("REMOTE CODE EXECUTION", "RCE"),
        ("CODE EXECUTION", "RCE"),
        ("COMMAND INJECTION", "command injection"),
        ("AUTHENTICATION BYPASS", "authentication bypass"),
        ("AUTH BYPASS", "auth bypass"),
        ("AUTHORIZATION BYPASS", "authorization bypass"),
        ("IMPROPER ACCESS CONTROL", "access control flaw"),
        ("ACCESS CONTROL", "access control flaw"),
        ("PRIVILEGE ESCALATION", "privilege escalation"),
        ("SQL INJECTION", "SQL injection"),
        ("CROSS-SITE SCRIPTING", "XSS"),
        ("XSS", "XSS"),
        ("PATH TRAVERSAL", "path traversal"),
        ("DIRECTORY TRAVERSAL", "directory traversal"),
        ("BUFFER OVERFLOW", "buffer overflow"),
        ("DENIAL OF SERVICE", "DoS"),
        ("INFORMATION DISCLOSURE", "info disclosure"),
        ("SENSITIVE DATA", "data exposure"),
        ("DESERIALIZATION", "unsafe deserialization"),
        ("PROTOTYPE POLLUTION", "prototype pollution"),
        ("SSRF", "SSRF"),
        ("SERVER-SIDE REQUEST FORGERY", "SSRF"),
        ("CSRF", "CSRF"),
        ("TOKEN", "token theft"),
        ("SESSION", "session hijacking"),
        ("CAMERA", "camera access"),
        ("OAUTH", "OAuth bypass"),
    ]

    for pattern, vuln_type in vuln_patterns:
        if pattern in desc_upper:
            return vuln_type

    return "security flaw"


def _extract_product_name(vuln: dict) -> str:
    """Extract a clean, short product name from vulnerability data."""
    vendor = vuln.get("vendor", "").strip()
    product = vuln.get("product", "").strip()
    title = vuln.get("title", "")

    if vendor:
        return vendor
    if product:
        return product

    # Try to extract from title (first few words before "versions" or numbers)
    if title:
        import re
        # Common patterns: "ProductName versions up to X.Y.Z"
        match = re.match(r'^([A-Za-z][A-Za-z0-9\s]+?)(?:\s+versions?|\s+v?\d|\s+up\s+to|\s+before|\s+through)', title, re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            # If name is too long (>25 chars), take just the first word/brand
            if len(name) > 25:
                words = name.split()
                # Return first word, or first two if first is very short
                if len(words[0]) < 4 and len(words) > 1:
                    return f"{words[0]} {words[1]}"
                return words[0]
            return name
        # Fallback: first 2 words
        words = title.split()[:2]
        return " ".join(words)

    return "Unknown"


def _is_iot_device(title: str, description: str) -> bool:
    """Check if vulnerability is about an IoT/smart device."""
    text = (title + " " + description).upper()
    iot_keywords = [
        "SMART", "IOT", "CONNECTED", "FEEDER", "THERMOSTAT", "CAMERA",
        "DOORBELL", "LOCK", "SPEAKER", "WATCH", "WEARABLE", "SENSOR",
        "PET", "BABY MONITOR", "IP CAMERA", "ROUTER", "HOME AUTOMATION"
    ]
    return any(kw in text for kw in iot_keywords)


def _get_theme_and_hook(vulns: list) -> tuple:
    """
    Analyze vulnerabilities to determine episode theme and alert hook.

    Returns:
        (theme_words, alert_hook) - e.g., ("IoT Camera", "Smart devices exposing homes...")
    """
    if not vulns:
        return "Security", "New vulnerabilities require your attention"

    # Collect info about all vulns
    products = []
    vuln_types = []
    has_iot = False
    has_critical = False
    has_rce = False
    has_camera = False

    for v in vulns:
        products.append(_extract_product_name(v))
        vtype = _extract_vuln_type(v.get("description", ""))
        vuln_types.append(vtype)

        title = v.get("title", "")
        desc = v.get("description", "")
        text = (title + " " + desc).upper()

        if _is_iot_device(title, desc):
            has_iot = True
        if v.get("cvss_score", 0) >= 9.0:
            has_critical = True
        if "RCE" in vtype.upper() or "CODE EXECUTION" in text:
            has_rce = True
        if "CAMERA" in text:
            has_camera = True

    # Determine theme based on content
    unique_products = list(dict.fromkeys(products))  # Remove dupes, keep order

    if has_iot and has_camera:
        theme = "IoT Camera"
        hook = "Smart devices with cameras are exposing homes to unauthorized surveillance"
    elif has_iot:
        theme = "IoT Security"
        hook = "Connected devices are under attack with multiple critical flaws"
    elif has_rce and has_critical:
        theme = "Critical RCE"
        hook = "Remote code execution vulnerabilities require immediate patching"
    elif has_critical:
        theme = "Critical Vulns"
        hook = "Critical severity vulnerabilities discovered - patch immediately"
    elif len(unique_products) == 1:
        theme = unique_products[0]
        hook = f"{unique_products[0]} faces multiple security vulnerabilities"
    elif len(unique_products) <= 3:
        theme = " + ".join(unique_products[:2])
        hook = f"Multiple products affected by new security flaws"
    else:
        theme = "Security Alert"
        hook = "New vulnerabilities require your attention"

    return theme, hook


def _generate_mock_metadata(daily_brief: dict) -> dict:
    """
    Generate metadata for YouTube without LLM.

    Creates engaging, informative metadata similar to:
    - Title: "ALERT: Smart Pet Feeder Camera Hack - Full Home Access (3 CVEs)"
    - Description with alert hook, CVE details, context, actions, hashtags
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stats = daily_brief.get("filter_stats", {})
    critical_count = stats.get("critical_count", 0)
    high_count = stats.get("high_count", 0)

    # Get theme and hook
    theme, hook = _get_theme_and_hook(vulns)

    # Build title
    num_cves = len(vulns)
    if critical_count > 0:
        prefix = "URGENT"
    elif high_count > 0:
        prefix = "ALERT"
    else:
        prefix = "Security Brief"

    if num_cves > 0:
        primary_title = f"{prefix}: {theme} Vulnerabilities ({num_cves} CVEs)"
    else:
        primary_title = f"{prefix}: Daily Security Brief"

    # Build description
    desc_lines = []

    # Alert hook
    desc_lines.append(f"🚨 ALERT: {hook}")
    desc_lines.append("")
    desc_lines.append("In today's brief:")
    desc_lines.append("")

    # CVE list with types and scores
    products_mentioned = set()
    actions = []

    for v in vulns[:5]:
        cvss = v.get("cvss_score", 0)
        cve_id = v.get("cve_id", "CVE-XXXX")
        desc = v.get("description", "")

        product = _extract_product_name(v)
        vuln_type = _extract_vuln_type(desc)
        products_mentioned.add(product)

        # Severity emoji and label
        if cvss >= 9.0:
            emoji = "🔴"
            severity = "CRITICAL"
        elif cvss >= 7.0:
            emoji = "🟠"
            severity = "HIGH"
        else:
            emoji = "🟡"
            severity = "MEDIUM"

        desc_lines.append(f"• {emoji} [{severity}] {cve_id}: {product} - {vuln_type} ({cvss})")

        # Build action item
        actions.append(f"☑️ Update/patch {product}")

    desc_lines.append("")

    # Context paragraph
    if _is_iot_device(vulns[0].get("title", ""), vulns[0].get("description", "")) if vulns else False:
        desc_lines.append("IoT and smart home devices continue to be soft targets. These vulnerabilities could allow attackers to access cameras, control devices, and compromise home networks.")
    else:
        desc_lines.append("These vulnerabilities highlight the ongoing need for prompt patching and security monitoring. Review your exposure and prioritize remediation.")

    desc_lines.append("")

    # Immediate actions (deduplicated)
    desc_lines.append("⚡ Immediate Actions:")
    seen_actions = set()
    for action in actions:
        if action not in seen_actions:
            desc_lines.append(action)
            seen_actions.add(action)
        if len(seen_actions) >= 4:
            break
    desc_lines.append("☑️ Review authentication logs")
    desc_lines.append("☑️ Monitor for exploitation attempts")

    desc_lines.append("")

    # Hashtags
    hashtags = ["#CyberSecurity", "#Infosec"]
    if _is_iot_device(vulns[0].get("title", ""), vulns[0].get("description", "")) if vulns else False:
        hashtags.extend(["#IoT", "#SmartHome", "#Privacy"])
    if critical_count > 0 or any(v.get("cvss_score", 0) >= 9.0 for v in vulns):
        hashtags.append("#RCE")
    hashtags.append("#CVE2025")
    desc_lines.append(" ".join(hashtags[:6]))

    desc_lines.append("")
    desc_lines.append("Hosted by AI Analysts Alex & Morgan.")

    # Generate tags for YouTube
    tags = ["cybersecurity", "infosec", "vulnerability", "CVE", "security news", "hacking"]
    for product in list(products_mentioned)[:3]:
        tags.append(product.lower())
    for v in vulns[:3]:
        if v.get("cve_id"):
            tags.append(v["cve_id"])

    return {
        "titles": [
            primary_title,
            f"{theme} Security Flaws Exposed ({num_cves} CVEs)",
            f"Patch Now: {num_cves} New Vulnerabilities Explained",
        ],
        "primary_title": primary_title,
        "description": "\n".join(desc_lines),
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

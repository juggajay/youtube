"""
Thumbnail Generator - Creates click-optimized YouTube thumbnails.

Uses dynamic text overlays based on highest-impact content:
- Compares vulnerability scores (vendor tier + CVSS) vs story impact scores
- Priority 1: Highest scoring item (vuln or story) wins
- Priority 2: Critical count fallback -> "[X] CRITICAL" (red)
- Priority 3: High count fallback -> "[X] HIGH RISK" (yellow)
- Priority 4: Quiet day -> "DAILY INTEL" (cyan)
"""

import os
import re
from pathlib import Path
from PIL import Image, ImageEnhance, ImageDraw, ImageFont, ImageOps

from ..utils import get_logger
from ..ingest.story_scoring import calculate_impact_score
from ..ingest.models import Story, StoryType
from .vendor_tiers import get_vendor_tier, get_tier_weight, TIER_1

logger = get_logger(__name__)

# --- CONFIGURATION ---
TIER_1_VENDORS = [
    "MICROSOFT", "APPLE", "GOOGLE", "AMAZON", "AWS",
    "NVIDIA", "OPENAI", "META", "CISCO", "LINUX",
    "SAMSUNG", "TESLA"
]


# --- VISUAL FX ---

def apply_color_grade(image: Image.Image) -> Image.Image:
    """Contrast +20%, Saturation +15%"""
    image = ImageEnhance.Contrast(image).enhance(1.20)
    image = ImageEnhance.Color(image).enhance(1.15)
    return image


def apply_vignette(image: Image.Image, intensity: float = 0.5) -> Image.Image:
    """
    Cinematic vignette: dark corners, clear center.
    Uses Image.radial_gradient (Pillow >= 9.2.0)
    """
    width, height = image.size

    # 1. Generate radial gradient (white center -> black edges)
    max_dim = max(width, height)
    gradient = Image.radial_gradient("L")
    gradient = gradient.resize((max_dim, max_dim), Image.Resampling.LANCZOS)

    # 2. Center-crop to image aspect ratio
    left = (max_dim - width) // 2
    top = (max_dim - height) // 2
    gradient = gradient.crop((left, top, left + width, top + height))

    # 3. Invert: black center -> white edges (alpha mask)
    mask = ImageOps.invert(gradient)

    # 4. Reduce intensity
    mask = mask.point(lambda p: int(p * intensity))

    # 5. Composite black layer using mask
    black_layer = Image.new("RGB", image.size, (0, 0, 0))
    image = image.convert("RGB")
    return Image.composite(black_layer, image, mask)


# --- TEXT RENDERING ---

def render_text(image: Image.Image, text: str, color: str, font_path: str) -> Image.Image:
    """Render bold text with stroke at bottom-left."""
    draw = ImageDraw.Draw(image)

    # Dynamic font sizing: 15% of height (108px on 720p)
    font_size = int(image.height * 0.15)

    try:
        font = ImageFont.truetype(font_path, font_size)
    except OSError:
        logger.warning(f"Font not found at {font_path}, using default")
        font = ImageFont.load_default()

    # Position: bottom-left with padding
    # Extra bottom padding (120px) to clear YouTube progress bar
    x = 80

    # Calculate text height for bottom alignment
    bbox = draw.textbbox((0, 0), text, font=font)
    text_height = bbox[3] - bbox[1]
    y = image.height - 120 - text_height

    # Modern Pillow: built-in stroke
    draw.text(
        (x, y),
        text,
        font=font,
        fill=color,
        stroke_width=6,
        stroke_fill="#000000"
    )

    return image


# --- KEYWORD EXTRACTION ---

# Keywords to look for in title/description when vendor field is empty
KEYWORD_MAP = {
    # Infrastructure
    "MAIL SERVER": "MAIL SERVER",
    "EMAIL SERVER": "EMAIL",
    "WEB SERVER": "WEB SERVER",
    "FILE TRANSFER": "FILE TRANSFER",
    "FILE UPLOAD": "FILE UPLOAD",
    # Products
    "WORDPRESS": "WORDPRESS",
    "APACHE": "APACHE",
    "NGINX": "NGINX",
    "TOMCAT": "TOMCAT",
    "EXCHANGE": "EXCHANGE",
    "SHAREPOINT": "SHAREPOINT",
    "ORACLE": "ORACLE",
    "VMWARE": "VMWARE",
    "CITRIX": "CITRIX",
    "FORTINET": "FORTINET",
    "PALO ALTO": "PALO ALTO",
    "CISCO": "CISCO",
    "JUNIPER": "JUNIPER",
    "IVANTI": "IVANTI",
    "MONGODB": "MONGODB",
    "MYSQL": "MYSQL",
    "POSTGRESQL": "POSTGRESQL",
    "REDIS": "REDIS",
    "KUBERNETES": "KUBERNETES",
    "DOCKER": "DOCKER",
    # Attack types (fallback)
    "REMOTE CODE EXECUTION": "RCE",
    "SQL INJECTION": "SQL INJECTION",
    "AUTHENTICATION BYPASS": "AUTH BYPASS",
    "PRIVILEGE ESCALATION": "PRIV ESC",
}


def _extract_keyword_from_text(text: str) -> str:
    """Extract a recognizable keyword from title/description."""
    text_upper = text.upper()

    # Check Tier-1 vendors first
    for vendor in TIER_1_VENDORS:
        if vendor in text_upper:
            return vendor

    # Check keyword map
    for keyword, display in KEYWORD_MAP.items():
        if keyword in text_upper:
            return display

    return ""


# --- SCORING HELPERS ---

def _calculate_vuln_score(vuln: dict) -> float:
    """
    Calculate a comparable score for a vulnerability.

    Factors:
    - CVSS score (0-10, scaled to 0-100)
    - Vendor tier weight multiplier

    Returns:
        Score 0-100
    """
    cvss = vuln.get("cvss_score", 0)
    vendor = vuln.get("vendor", "")
    product = vuln.get("product", "")

    # Get vendor tier (check both vendor and product)
    tier = get_vendor_tier(vendor)
    if tier == 4:  # Unknown vendor, try product
        tier = get_vendor_tier(product)

    tier_weight = get_tier_weight(tier)

    # Scale CVSS to 0-100 and apply tier weight
    base_score = cvss * 10
    return base_score * tier_weight


def _story_dict_to_model(story_dict: dict) -> Story:
    """Convert a story dict to a Story model for scoring."""
    story_type_str = story_dict.get("story_type", "general")
    try:
        story_type = StoryType(story_type_str)
    except ValueError:
        story_type = StoryType.GENERAL

    return Story(
        id=story_dict.get("id", "thumbnail-temp"),
        title=story_dict.get("title", ""),
        summary=story_dict.get("summary", ""),
        story_type=story_type,
    )


def _extract_dollar_amount(text: str) -> str:
    """Extract dollar amount from text for display."""
    # Look for patterns like "$8.5 Million", "$50M", "$2 Billion"
    patterns = [
        r'(\$\d+(?:\.\d+)?\s*(?:BILLION|B\b))',
        r'(\$\d+(?:\.\d+)?\s*(?:MILLION|M\b))',
        r'(\$\d+(?:\.\d+)?(?:\s*(?:MILLION|BILLION|M|B))?)',
    ]
    text_upper = text.upper()
    for pattern in patterns:
        match = re.search(pattern, text_upper)
        if match:
            return match.group(1)
    return ""


def _format_story_text(story_dict: dict) -> str:
    """Format story into compelling thumbnail text."""
    title = story_dict.get("title", "")
    title_upper = title.upper()

    # Priority 1: Include dollar amounts
    dollar_amount = _extract_dollar_amount(title)
    if dollar_amount:
        # Try to extract company/entity name
        words = title.split()
        entity = ""
        for word in words:
            clean_word = word.upper().strip(",:;")
            if clean_word and not clean_word.startswith("$") and clean_word not in [
                "LOSES", "LOST", "STOLEN", "HACK", "BREACH", "ATTACK", "IN", "THE", "A"
            ]:
                entity = clean_word
                break
        if entity:
            return f"{entity} {dollar_amount}"
        return f"{dollar_amount} BREACH"

    # Priority 2: Check for Tier 1 vendor mentions
    for vendor in TIER_1:
        if vendor in title_upper:
            story_type = story_dict.get("story_type", "")
            suffix = "BREACH" if story_type == "breach" else "ALERT"
            return f"{vendor} {suffix}"

    # Priority 3: Nation-state/APT
    apt_patterns = [
        (r'(CHINA)[\s-]?(?:LINKED|NEXUS|BACKED)', 'CHINA-LINKED'),
        (r'(RUSSIA)[\s-]?(?:LINKED|NEXUS|BACKED)', 'RUSSIA-LINKED'),
        (r'(IRAN)[\s-]?(?:LINKED|NEXUS|BACKED)', 'IRAN-LINKED'),
        (r'(APT\d+)', None),  # Use matched group directly
        (r'(VOLT\s*TYPHOON|FANCY\s*BEAR|LAZARUS)', None),
    ]
    for pattern, replacement in apt_patterns:
        match = re.search(pattern, title_upper)
        if match:
            apt_name = replacement if replacement else match.group(1)
            return f"{apt_name} THREAT"

    # Priority 4: Ransomware
    if "RANSOMWARE" in title_upper:
        return "RANSOMWARE ALERT"

    # Priority 5: Generic breach/hack
    if "BREACH" in title_upper or "HACK" in title_upper or "STOLEN" in title_upper:
        words = title.split()[:2]
        company = " ".join(words).upper().replace(":", "").replace(",", "")
        return f"{company} BREACH"

    # Fallback: First few words
    words = title.split()[:3]
    return " ".join(words).upper()


def _format_vuln_text(vuln: dict) -> tuple:
    """
    Format vulnerability into thumbnail text with color.

    Returns:
        (text, hex_color)
    """
    vendor = vuln.get("vendor", "").upper().strip()
    product = vuln.get("product", "").upper().strip()
    cvss = vuln.get("cvss_score", 0)

    # Prefer vendor, fall back to product
    name = vendor if vendor else product

    # Check for Tier-1 vendor match (use full name)
    for t1 in TIER_1_VENDORS:
        if t1 in vendor or t1 in product:
            name = t1
            break

    # If still no name, try to extract from title/description
    if not name:
        title = vuln.get("title", "")
        description = vuln.get("description", "")
        name = _extract_keyword_from_text(title + " " + description)

    if not name:
        name = "VULNERABILITY"

    # Determine severity label and color
    if cvss >= 9.0:
        return f"{name} CRITICAL", "#FF0000"
    elif cvss >= 7.0:
        return f"{name} HIGH RISK", "#FFD700"
    else:
        return f"{name} ALERT", "#FFA500"


# --- PRIORITY LOGIC ---

def determine_text(daily_brief: dict) -> tuple:
    """
    Returns (text, hex_color) based on highest-impact content.

    Logic:
    1. Score all vulnerabilities (CVSS * tier_weight)
    2. Score all stories using calculate_impact_score
    3. Compare highest vuln score vs highest story score
    4. Winner determines the thumbnail text
    5. Fall back to counts or "DAILY INTEL" if nothing compelling

    Examples:
    - "$8.5M BREACH" (red) - high-impact story
    - "MICROSOFT CRITICAL" (red) - Tier 1 critical vuln
    - "CHINA-LINKED THREAT" (red) - APT story
    - "5 CRITICAL" (red) - fallback to counts
    - "DAILY INTEL" (cyan) - quiet day
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stories = daily_brief.get("top_stories", [])

    best_vuln_score = 0
    best_vuln = None
    best_story_score = 0
    best_story = None

    # --- Score vulnerabilities ---
    for vuln in vulns:
        score = _calculate_vuln_score(vuln)
        if score > best_vuln_score:
            best_vuln_score = score
            best_vuln = vuln

    # --- Score stories ---
    for story_dict in stories:
        if not isinstance(story_dict, dict):
            continue
        story_model = _story_dict_to_model(story_dict)
        score = calculate_impact_score(story_model)
        if score > best_story_score:
            best_story_score = score
            best_story = story_dict

    # --- Compare and pick winner ---
    if best_vuln_score > 0 or best_story_score > 0:
        if best_vuln_score >= best_story_score and best_vuln:
            # Vulnerability wins
            return _format_vuln_text(best_vuln)
        elif best_story:
            # Story wins
            text = _format_story_text(best_story)
            return text, "#FF0000"  # Stories are always red (high urgency)

    # --- Fallback: counts ---
    stats = daily_brief.get("filter_stats", {})
    critical_count = stats.get("critical_count", 0)
    high_count = stats.get("high_count", 0)

    if critical_count > 0:
        return f"{critical_count} CRITICAL", "#FF0000"
    if high_count > 0:
        return f"{high_count} HIGH RISK", "#FFD700"

    # --- Quiet day ---
    return "DAILY INTEL", "#00FFFF"


# --- MAIN ORCHESTRATOR ---

def generate_thumbnail(
    daily_brief: dict,
    output_dir: str,
    background_path: str = None,
    font_path: str = None,
) -> dict:
    """
    Generate a YouTube thumbnail for an episode.

    Args:
        daily_brief: Parsed daily_brief_packet.json
        output_dir: Directory to save thumbnail
        background_path: Path to background image (default: assets/background.png)
        font_path: Path to .ttf font (default: assets/impact.ttf)

    Returns:
        thumbnail_manifest dict
    """
    episode_date = daily_brief.get("date", "unknown")
    logger.info(f"Generating thumbnail for {episode_date}...")

    # Default paths
    assets_dir = Path("assets")
    if not background_path:
        background_path = str(assets_dir / "background.png")
    if not font_path:
        font_path = str(assets_dir / "impact.ttf")
        # Fallback to Windows system font
        if not os.path.exists(font_path):
            font_path = "C:/Windows/Fonts/impact.ttf"

    # 1. Load Background
    if not os.path.exists(background_path):
        raise FileNotFoundError(f"Missing background image at {background_path}")

    img = Image.open(background_path).convert("RGB")

    # 2. Smart Resize (Center Crop to 1280x720)
    img = ImageOps.fit(img, (1280, 720), method=Image.Resampling.LANCZOS)

    # 3. Apply Visual FX
    img = apply_color_grade(img)
    img = apply_vignette(img, intensity=0.5)

    # 4. Determine Text
    text_content, text_color = determine_text(daily_brief)
    logger.info(f"Text: [{text_content}] ({text_color})")

    # 5. Render Text
    img = render_text(img, text_content, text_color, font_path)

    # 6. Save
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    thumbnail_path = output_path / "thumbnail.png"
    img.save(str(thumbnail_path))

    logger.info(f"Thumbnail saved: {thumbnail_path}")

    # Return manifest
    manifest = {
        "episode_date": episode_date,
        "thumbnail_file": str(thumbnail_path),
        "resolution": "1280x720",
        "text_overlay": text_content,
        "text_color": text_color,
        "sources": {
            "background": background_path,
            "daily_brief": "daily_brief_packet.json",
        }
    }

    return manifest


# --- TEST HARNESS ---
if __name__ == "__main__":
    import json

    # Test with existing episode data
    test_path = "output/episodes/2025-01-01/daily_brief_packet.json"
    if os.path.exists(test_path):
        with open(test_path) as f:
            data = json.load(f)
        result = generate_thumbnail(data, "output/episodes/2025-01-01")
        print(json.dumps(result, indent=2))
    else:
        # Mock data
        mock_data = {
            "date": "2025-12-29",
            "vulnerabilities": [],
            "filter_stats": {"critical_count": 5, "high_count": 12}
        }
        result = generate_thumbnail(mock_data, "output/thumbnails")
        print(json.dumps(result, indent=2))

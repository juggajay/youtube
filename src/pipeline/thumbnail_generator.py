"""
Thumbnail Generator - Creates click-optimized YouTube thumbnails.

Uses dynamic text overlays based on episode severity:
- Priority 1: Tier-1 vendor -> "PATCH [VENDOR]" (red)
- Priority 2: Critical count -> "[X] CRITICAL" (red)
- Priority 3: High count -> "[X] HIGH RISK" (yellow)
- Priority 4: Quiet day -> "DAILY INTEL" (cyan)
"""

import os
from pathlib import Path
from PIL import Image, ImageEnhance, ImageDraw, ImageFont, ImageOps

from ..utils import get_logger

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


# --- PRIORITY LOGIC ---

def determine_text(daily_brief: dict) -> tuple:
    """
    Returns (text, hex_color) based on top threat.

    Logic:
    1. Find highest severity CVE and extract vendor name
    2. If vendor empty, try to extract from title/description
    3. Fall back to top news story if no CVEs
    4. "DAILY INTEL" for quiet days

    Examples:
    - "MONGODB CRITICAL" (red)
    - "MAIL SERVER CRITICAL" (red)
    - "CISCO HIGH RISK" (yellow)
    - "CONDE NAST BREACH" (red)
    - "DAILY INTEL" (cyan)
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stories = daily_brief.get("top_stories", [])

    # --- Priority 1: Find top CVE by severity ---
    if vulns:
        # Sort by CVSS score descending
        sorted_vulns = sorted(
            vulns,
            key=lambda v: v.get("cvss_score", 0),
            reverse=True
        )
        top_vuln = sorted_vulns[0]
        cvss = top_vuln.get("cvss_score", 0)

        # Extract vendor name (clean it up)
        vendor = top_vuln.get("vendor", "").upper().strip()
        product = top_vuln.get("product", "").upper().strip()

        # Prefer vendor, fall back to product
        name = vendor if vendor else product

        # Check for Tier-1 vendor match (use full name)
        for t1 in TIER_1_VENDORS:
            if t1 in vendor or t1 in product:
                name = t1
                break

        # If still no name, try to extract from title/description
        if not name:
            title = top_vuln.get("title", "")
            description = top_vuln.get("description", "")
            name = _extract_keyword_from_text(title + " " + description)

        if name:
            # Determine severity label
            if cvss >= 9.0:
                return f"{name} CRITICAL", "#FF0000"
            elif cvss >= 7.0:
                return f"{name} HIGH RISK", "#FFD700"
            else:
                return f"{name} ALERT", "#FFA500"

    # --- Priority 2: Check for breach/news stories ---
    if stories:
        top_story = stories[0] if isinstance(stories[0], dict) else {"title": str(stories[0])}
        title = top_story.get("title", "").upper()

        # Check for breach keywords
        if "BREACH" in title or "HACK" in title or "LEAK" in title or "STOLEN" in title:
            # Try to extract company name (first 1-2 words usually)
            words = title.split()[:2]
            company = " ".join(words).replace(":", "").replace(",", "")
            return f"{company} BREACH", "#FF0000"

        # Check for ransomware
        if "RANSOMWARE" in title:
            return "RANSOMWARE ALERT", "#FF0000"

    # --- Priority 3: Fall back to counts if we have them ---
    stats = daily_brief.get("filter_stats", {})
    critical_count = stats.get("critical_count", 0)
    high_count = stats.get("high_count", 0)

    if critical_count > 0:
        return f"{critical_count} CRITICAL", "#FF0000"
    if high_count > 0:
        return f"{high_count} HIGH RISK", "#FFD700"

    # --- Priority 4: Quiet day ---
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

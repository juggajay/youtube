"""
Thumbnail Generator - Creates click-optimized YouTube thumbnails.

Uses dynamic text overlays based on highest-impact content:
- Priority 1: CISA KEV vulnerabilities -> "{VENDOR} CRITICAL" (red)
- Priority 2: Breach stories with dollar amounts -> "$X STOLEN" (red)
- Priority 3: Critical CVEs (9.0+) with clear vendor -> "{VENDOR} CRITICAL" (red)
- Priority 4: APT/nation-state stories -> "{APT} THREAT" (red)
- Priority 5: High CVEs (7.0+) with clear vendor -> "{VENDOR} HIGH RISK" (yellow)
- Priority 6: IoT/consumer device vulns -> "IOT ALERT" or "SMART HOME FLAW" (orange)
- Priority 7: Attack type fallback -> "AUTH BYPASS", "CAMERA HACK" (orange)
- Priority 8: Count fallback -> "[X] CRITICAL" or "[X] HIGH RISK"
- Priority 9: Quiet day -> "DAILY INTEL" (cyan)

Key design decisions:
- Only extract Tier 1 vendors from TITLE (not description) to avoid false positives
- Filter out third-party mentions like "via Google OAuth" or "Google IDs"
- IoT devices get special treatment even if vendor is unknown
- Attack types provide meaningful fallback headlines
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
}

# IoT/Smart device keywords - triggers special IoT headlines
IOT_KEYWORDS = [
    "SMART", "IOT", "CONNECTED DEVICE", "FEEDER", "THERMOSTAT",
    "DOORBELL", "SMART LOCK", "SMART SPEAKER", "SMARTWATCH", "WEARABLE",
    "SENSOR", "HOME AUTOMATION", "ZIGBEE", "Z-WAVE",
    "PET CAM", "PET FEEDER", "BABY MONITOR", "SECURITY CAMERA", "IP CAMERA",
    "SMART TV", "SMART PLUG", "SMART LIGHT", "SMART HOME",
    "RING", "NEST", "ECOBEE", "WYZE", "BLINK", "ARLO",
]

# Attack types for fallback headlines (more specific than generic "VULNERABILITY")
ATTACK_TYPE_HEADLINES = {
    # Auth/Access issues
    "AUTHENTICATION BYPASS": "AUTH BYPASS",
    "AUTH BYPASS": "AUTH BYPASS",
    "AUTHORIZATION BYPASS": "AUTH BYPASS",
    "ACCOUNT TAKEOVER": "ACCOUNT TAKEOVER",
    "SESSION HIJACK": "SESSION HIJACK",
    "OAUTH": "AUTH BYPASS",  # OAuth issues are auth bypasses
    # Camera/surveillance
    "CAMERA ACCESS": "CAMERA HACK",
    "CAMERA FEED": "CAMERA HACK",
    "VIDEO FEED": "CAMERA HACK",
    "SURVEILLANCE": "CAMERA HACK",
    # Code execution
    "REMOTE CODE EXECUTION": "RCE ALERT",
    "CODE EXECUTION": "RCE ALERT",
    "COMMAND INJECTION": "RCE ALERT",
    "ARBITRARY CODE": "RCE ALERT",
    # Injection
    "SQL INJECTION": "SQL INJECTION",
    "XSS": "XSS ALERT",
    "CROSS-SITE SCRIPTING": "XSS ALERT",
    # Privilege
    "PRIVILEGE ESCALATION": "PRIV ESC",
    "PRIVESC": "PRIV ESC",
    "ROOT ACCESS": "PRIV ESC",
    "ADMIN ACCESS": "PRIV ESC",
    # Data
    "DATA LEAK": "DATA LEAK",
    "DATA EXPOSURE": "DATA EXPOSED",
    "INFORMATION DISCLOSURE": "DATA EXPOSED",
    "SENSITIVE DATA": "DATA EXPOSED",
}

# Third-party context patterns - if vendor appears in these contexts, it's NOT the subject
THIRD_PARTY_PATTERNS = [
    r'VIA\s+{vendor}',
    r'USING\s+{vendor}',
    r'WITH\s+{vendor}',
    r'THROUGH\s+{vendor}',
    r'{vendor}\s+IDS?\b',
    r'{vendor}\s+OAUTH',
    r'{vendor}\s+LOGIN',
    r'{vendor}\s+ACCOUNT',
    r'{vendor}\s+SIGN[- ]?IN',
    r'{vendor}\s+AUTH(?:ENTICATION)?(?!\s+BYPASS)',  # "Google Auth" but not "Google Authentication Bypass"
    r'{vendor}\s+SSO',
    r'{vendor}\s+TOKEN',
    r'{vendor}\s+API(?!\s+VULN)',  # "Google API" but not "Google API Vulnerability"
]


def _is_vendor_third_party(vendor: str, text: str) -> bool:
    """
    Check if a vendor appears in a third-party context (not the vulnerable product).

    Examples of third-party context:
    - "OAuth bypass via Google IDs" -> Google is third party
    - "using Google authentication" -> Google is third party
    - "Google Chrome vulnerability" -> Google is the subject (return False)
    """
    text_upper = text.upper()
    vendor_upper = vendor.upper()

    for pattern_template in THIRD_PARTY_PATTERNS:
        pattern = pattern_template.format(vendor=re.escape(vendor_upper))
        if re.search(pattern, text_upper):
            return True

    return False


def _is_iot_device(title: str, description: str) -> bool:
    """Check if vulnerability is about an IoT/smart/connected device."""
    text_upper = (title + " " + description).upper()
    for keyword in IOT_KEYWORDS:
        if keyword in text_upper:
            return True
    return False


def _get_iot_headline(title: str, description: str) -> str:
    """
    Get an appropriate headline for IoT device vulnerabilities.

    Returns specific headlines based on device type, or generic IoT headline.
    Priority: Camera > Baby Monitor > Home Security > Pet devices > Generic
    """
    text_upper = (title + " " + description).upper()

    # Camera-related (highest priority - privacy concern)
    if any(kw in text_upper for kw in ["CAMERA", "CAM", "VIDEO FEED", "SURVEILLANCE"]):
        return "IOT CAMERA HACK"

    # Baby monitors (high privacy concern)
    if "BABY MONITOR" in text_upper:
        return "BABY MONITOR FLAW"

    # Home security
    if any(kw in text_upper for kw in ["DOORBELL", "LOCK", "ALARM", "SECURITY SYSTEM"]):
        return "SMART HOME FLAW"

    # Pet devices
    if any(kw in text_upper for kw in ["PET", "FEEDER"]):
        return "IOT DEVICE FLAW"

    # Generic IoT
    return "IOT ALERT"


def _get_best_iot_headline_from_vulns(vulns: list) -> str:
    """
    Check all vulnerabilities and return the best IoT headline.

    Prioritizes more specific/alarming headlines like "IOT CAMERA HACK"
    over generic ones like "IOT DEVICE FLAW".
    """
    # Headline priority (most alarming first)
    headline_priority = [
        "IOT CAMERA HACK",
        "BABY MONITOR FLAW",
        "SMART HOME FLAW",
        "IOT DEVICE FLAW",
        "IOT ALERT",
    ]

    best_headline = None
    best_priority = len(headline_priority)  # Lower is better

    for vuln in vulns:
        title = vuln.get("title", "")
        description = vuln.get("description", "")

        if _is_iot_device(title, description):
            headline = _get_iot_headline(title, description)
            try:
                priority = headline_priority.index(headline)
                if priority < best_priority:
                    best_priority = priority
                    best_headline = headline
            except ValueError:
                # Unknown headline, use if we have nothing better
                if not best_headline:
                    best_headline = headline

    return best_headline or "IOT ALERT"


def _get_attack_type_headline(title: str, description: str) -> str:
    """
    Extract attack type for a meaningful fallback headline.

    Better than "VULNERABILITY" - tells viewer what kind of attack.
    """
    text_upper = (title + " " + description).upper()

    for pattern, headline in ATTACK_TYPE_HEADLINES.items():
        if pattern in text_upper:
            return headline

    return ""


def _extract_vendor_from_title(title: str) -> str:
    """
    Extract Tier 1 vendor from TITLE ONLY, with third-party filtering.

    Only checks title (not description) to avoid false positives like
    "Google IDs" in a Petlibro vulnerability description.
    """
    title_upper = title.upper()

    for vendor in TIER_1_VENDORS:
        if vendor in title_upper:
            # Make sure it's not in a third-party context
            if not _is_vendor_third_party(vendor, title):
                return vendor

    return ""


def _extract_keyword_from_text(text: str, title_only: str = "") -> str:
    """
    Extract a recognizable keyword from text.

    Args:
        text: Full text (title + description) for keyword map search
        title_only: Title text for Tier 1 vendor extraction (safer)

    Returns:
        Extracted keyword or empty string
    """
    text_upper = text.upper()

    # For Tier 1 vendors, only check title to avoid false positives
    if title_only:
        vendor = _extract_vendor_from_title(title_only)
        if vendor:
            return vendor

    # Check keyword map (products, infrastructure)
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
    - Critical severity boost (CVSS 9.0+ gets minimum 0.7 weight)
    - IoT device boost (consumer relevance even if unknown vendor)

    Returns:
        Score 0-100
    """
    cvss = vuln.get("cvss_score", 0)
    vendor = vuln.get("vendor", "")
    product = vuln.get("product", "")
    title = vuln.get("title", "")
    description = vuln.get("description", "")

    # Get vendor tier (check vendor, product, then TITLE ONLY for Tier 1)
    tier = get_vendor_tier(vendor)
    if tier == 4:  # Unknown vendor, try product
        tier = get_vendor_tier(product)
    if tier == 4:  # Still unknown, try to extract from TITLE only (not description)
        # This prevents "Google IDs" in description from matching "GOOGLE"
        extracted = _extract_keyword_from_text(title + " " + description, title_only=title)
        if extracted:
            tier = get_vendor_tier(extracted)

    tier_weight = get_tier_weight(tier)

    # CRITICAL FIX: High severity vulns (CVSS 9.0+) should not be buried
    # by tier weighting. Apply minimum weight of 0.7 for critical vulns.
    if cvss >= 9.0 and tier_weight < 0.7:
        tier_weight = 0.7

    # IoT device boost: consumer-relevant even if unknown vendor
    # IoT vulns get minimum 0.6 weight (Tier 3 equivalent)
    if tier == 4 and _is_iot_device(title, description):
        tier_weight = max(tier_weight, 0.6)

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


def _is_breach_or_loss_story(title: str, summary: str) -> bool:
    """
    Check if a story is about a breach, theft, or financial loss.

    Returns True for: breaches, hacks, theft, ransoms, fraud, fines
    Returns False for: discounts, savings, free offers, prices, costs
    """
    text_upper = (title + " " + summary).upper()

    # Negative keywords - these indicate it's NOT a breach/loss story
    # Skip stories about discounts, savings, promotions
    negative_keywords = [
        "SAVE", "SAVING", "SAVINGS", "DISCOUNT", "FREE MONTH", "FREE TRIAL",
        "OFFER", "DEAL", "CANCEL", "SUBSCRIPTION", "PRICE", "PRICING",
        "COST", "COSTS", "WORTH", "VALUE", "BUDGET", "AFFORDABLE",
    ]
    for keyword in negative_keywords:
        if keyword in text_upper:
            return False

    # Positive keywords - these indicate it IS a breach/loss story
    positive_keywords = [
        "STOLEN", "THEFT", "BREACH", "HACK", "HACKED", "ATTACK",
        "LOST", "LOSS", "LOSES", "DRAIN", "DRAINED", "RANSOM",
        "RANSOMWARE", "FRAUD", "HEIST", "COMPROMISE", "COMPROMISED",
        "FINE", "FINED", "PENALTY", "SETTLEMENT", "SUED", "LAWSUIT",
        "LEAK", "LEAKED", "EXPOSED", "EXTORT", "VICTIM",
    ]
    for keyword in positive_keywords:
        if keyword in text_upper:
            return True

    # Default: if no clear signal, don't prioritize
    return False


def _format_story_text(story_dict: dict) -> str:
    """Format story into compelling thumbnail text."""
    title = story_dict.get("title", "")
    summary = story_dict.get("summary", "")
    title_upper = title.upper()
    full_text = title + " " + summary

    # Priority 1: Dollar amounts - most click-worthy
    # Format: "$8.5M STOLEN" or "TRUST WALLET $8.5M"
    dollar_amount = _extract_dollar_amount(full_text)
    if dollar_amount:
        # Normalize to compact format: "$8.5M" not "$8.5 MILLION"
        compact_dollar = dollar_amount.replace(" MILLION", "M").replace(" BILLION", "B")
        compact_dollar = compact_dollar.replace("MILLION", "M").replace("BILLION", "B")

        # Check for known company names in title
        known_companies = [
            "TRUST WALLET", "COINBASE", "BINANCE", "OPENSEA", "METAMASK",
            "UBER", "TWITTER", "FACEBOOK", "INSTAGRAM", "WHATSAPP",
            "DISNEY", "SONY", "MICROSOFT", "APPLE", "GOOGLE", "AMAZON",
        ]
        for company in known_companies:
            if company in title_upper:
                return f"{company} {compact_dollar}"

        # Check for action words to create compelling text
        if "STOLEN" in title_upper or "DRAIN" in title_upper or "HACK" in title_upper:
            return f"{compact_dollar} STOLEN"
        elif "LOST" in title_upper or "LOSES" in title_upper:
            return f"{compact_dollar} LOST"
        elif "BREACH" in title_upper:
            return f"{compact_dollar} BREACH"
        elif "FINE" in title_upper or "PENALTY" in title_upper or "SETTLE" in title_upper:
            return f"{compact_dollar} FINE"
        else:
            # Generic: try to get first word as entity
            words = title.split()
            for word in words:
                clean = word.upper().strip(",:;'\"")
                if clean and len(clean) > 2 and not clean.startswith("$"):
                    if clean not in ["THE", "AND", "FOR", "WITH", "FROM", "AFTER"]:
                        return f"{clean} {compact_dollar}"
            return f"{compact_dollar} BREACH"

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
        (r'(NORTH\s*KOREA)[\s-]?(?:LINKED|NEXUS|BACKED)', 'DPRK-LINKED'),
        (r'(APT\d+)', None),  # Use matched group directly
        (r'(VOLT\s*TYPHOON|FANCY\s*BEAR|LAZARUS|SANDWORM)', None),
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


def _format_vuln_text(vuln: dict, force_red: bool = False) -> tuple:
    """
    Format vulnerability into thumbnail text with color.

    Priority for headline text:
    1. Structured vendor/product field
    2. Tier 1 vendor in TITLE (not description)
    3. IoT device headline
    4. Attack type headline
    5. Product keyword from keyword map
    6. Generic "VULNERABILITY"

    Args:
        vuln: Vulnerability dict
        force_red: Force red color (e.g., CISA KEV in episode)

    Returns:
        (text, hex_color)
    """
    vendor = vuln.get("vendor", "").upper().strip()
    product = vuln.get("product", "").upper().strip()
    cvss = vuln.get("cvss_score", 0)
    is_kev = vuln.get("cisa_kev", False)
    title = vuln.get("title", "")
    description = vuln.get("description", "")

    # Priority 1: Prefer structured vendor/product field
    name = vendor if vendor else product

    # Priority 2: Check for Tier-1 vendor match in structured fields
    for t1 in TIER_1_VENDORS:
        if t1 in vendor or t1 in product:
            name = t1
            break

    # Priority 3: Extract Tier 1 vendor from TITLE only (not description)
    # This prevents "Google IDs" in description from matching "GOOGLE"
    if not name:
        name = _extract_vendor_from_title(title)

    # Priority 4: IoT device - use specific IoT headline
    if not name and _is_iot_device(title, description):
        iot_headline = _get_iot_headline(title, description)
        # IoT headlines are complete (e.g., "IOT CAMERA HACK")
        # Return directly with appropriate color
        if is_kev or force_red or cvss >= 9.0:
            return iot_headline, "#FF0000"
        elif cvss >= 7.0:
            return iot_headline, "#FFA500"  # Orange for IoT high risk
        else:
            return iot_headline, "#FFA500"

    # Priority 5: Attack type headline (e.g., "AUTH BYPASS", "CAMERA HACK")
    if not name:
        attack_headline = _get_attack_type_headline(title, description)
        if attack_headline:
            # Attack type headlines are complete
            if is_kev or force_red or cvss >= 9.0:
                return attack_headline, "#FF0000"
            elif cvss >= 7.0:
                return attack_headline, "#FFA500"
            else:
                return attack_headline, "#FFA500"

    # Priority 6: Product keyword from keyword map
    if not name:
        name = _extract_keyword_from_text(title + " " + description)

    # Fallback: generic
    if not name:
        name = "VULNERABILITY"

    # Determine severity label and color
    # CISA KEV or force_red always = red
    if is_kev or force_red:
        return f"{name} CRITICAL", "#FF0000"
    elif cvss >= 9.0:
        return f"{name} CRITICAL", "#FF0000"
    elif cvss >= 7.0:
        return f"{name} HIGH RISK", "#FFD700"
    else:
        return f"{name} ALERT", "#FFA500"


# --- PRIORITY LOGIC ---

def determine_text(daily_brief: dict) -> tuple:
    """
    Returns (text, hex_color) based on highest-impact content.

    Priority order (designed to highlight what viewers care about):
    1. CISA KEV vulnerabilities - must-patch urgency (red)
    2. Breach stories with dollar amounts - "$8.5M STOLEN" (red)
    3. Critical CVEs (9.0+) with clear vendor - "{VENDOR} CRITICAL" (red)
    4. APT/nation-state stories - geopolitical significance (red)
    5. IoT/consumer device vulns - "IOT CAMERA HACK" etc (orange)
    6. Highest scoring vuln/story - based on CVSS × tier weight
    7. Count fallback - "X CRITICAL" or "X HIGH RISK"
    8. Quiet day - "DAILY INTEL" (cyan)

    Key design decisions:
    - Only extract Tier 1 vendors from TITLE (not description)
    - Filter out third-party mentions like "via Google OAuth"
    - IoT devices get best headline across all vulns ("IOT CAMERA HACK" beats "IOT DEVICE FLAW")
    - Attack types provide meaningful fallback in _format_vuln_text

    Color rules:
    - Red (#FF0000): CISA KEV, CVSS 9.0+, major breaches, dollar amounts
    - Yellow (#FFD700): CVSS 7.0-8.9, high risk, known vendors
    - Orange (#FFA500): IoT devices, attack types, notable but not critical
    - Cyan (#00FFFF): Quiet day fallback
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stories = daily_brief.get("top_stories", [])

    # --- Check for CISA KEV (forces red for entire episode) ---
    has_kev = any(vuln.get("cisa_kev", False) for vuln in vulns)

    # --- Priority 1: CISA KEV vulnerability (highest urgency) ---
    for vuln in vulns:
        if vuln.get("cisa_kev", False):
            return _format_vuln_text(vuln, force_red=True)

    # --- Priority 2: Breach stories with dollar amounts ---
    # "$8.5M STOLEN" is click-worthy, but "$20 savings" is not
    best_dollar_story = None
    best_dollar_amount = ""
    for story_dict in stories:
        if not isinstance(story_dict, dict):
            continue
        title = story_dict.get("title", "")
        summary = story_dict.get("summary", "")

        # Only consider dollar amounts from breach/theft/loss stories
        if not _is_breach_or_loss_story(title, summary):
            continue

        dollar = _extract_dollar_amount(title + " " + summary)
        if dollar:
            # Prefer larger amounts (rough heuristic: longer string = bigger number)
            if not best_dollar_amount or len(dollar) > len(best_dollar_amount):
                best_dollar_amount = dollar
                best_dollar_story = story_dict

    if best_dollar_story:
        text = _format_story_text(best_dollar_story)
        return text, "#FF0000"  # Breach dollar amounts always red

    # --- Priority 3: Critical CVE (9.0+) with clear vendor ---
    for vuln in vulns:
        cvss = vuln.get("cvss_score", 0)
        if cvss >= 9.0:
            vendor = vuln.get("vendor", "").strip()
            product = vuln.get("product", "").strip()
            title = vuln.get("title", "")

            # Check if we have a clear vendor (not just from description context)
            has_clear_vendor = bool(vendor or product or _extract_vendor_from_title(title))
            if has_clear_vendor:
                return _format_vuln_text(vuln, force_red=True)

    # --- Priority 4: APT/nation-state stories ---
    for story_dict in stories:
        if not isinstance(story_dict, dict):
            continue
        title = story_dict.get("title", "").upper()
        story_type = story_dict.get("story_type", "")

        # Check for APT indicators
        apt_indicators = [
            "APT", "NATION-STATE", "CHINA-LINKED", "RUSSIA-LINKED",
            "IRAN-LINKED", "NORTH KOREA", "LAZARUS", "FANCY BEAR",
            "VOLT TYPHOON", "SANDWORM", "COZY BEAR", "STATE-SPONSORED"
        ]
        if story_type == "apt" or any(ind in title for ind in apt_indicators):
            text = _format_story_text(story_dict)
            return text, "#FF0000"

    # --- Priority 5: IoT device vulnerabilities (check all vulns) ---
    # IoT vulns are consumer-relevant even if vendor is unknown
    any_iot = any(_is_iot_device(v.get("title", ""), v.get("description", "")) for v in vulns)
    if any_iot:
        # Get best IoT headline across all vulns
        iot_headline = _get_best_iot_headline_from_vulns(vulns)
        # Find the highest CVSS among IoT vulns to determine color
        max_iot_cvss = max(
            (v.get("cvss_score", 0) for v in vulns
             if _is_iot_device(v.get("title", ""), v.get("description", ""))),
            default=0
        )
        if max_iot_cvss >= 9.0:
            return iot_headline, "#FF0000"
        elif max_iot_cvss >= 7.0:
            return iot_headline, "#FFA500"
        else:
            return iot_headline, "#FFA500"

    # --- Priority 6: Score remaining vulns and stories ---
    best_vuln_score = 0
    best_vuln = None
    best_story_score = 0
    best_story = None

    for vuln in vulns:
        score = _calculate_vuln_score(vuln)
        if score > best_vuln_score:
            best_vuln_score = score
            best_vuln = vuln

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
        # Stories need to beat vulns by a margin to win (vulns are core content)
        if best_story_score > best_vuln_score * 1.2 and best_story:
            # Story wins (needs 20% higher score)
            text = _format_story_text(best_story)
            return text, "#FF0000"
        elif best_vuln:
            # Vulnerability wins - _format_vuln_text handles attack types
            return _format_vuln_text(best_vuln, force_red=has_kev)

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

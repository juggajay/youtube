"""
Vendor Tier Classification System.

Tiers determine relevance weighting in vulnerability filtering:
- Tier 1 (weight 1.0): Massive install base, affects most viewers
- Tier 2 (weight 0.8): Enterprise security/infrastructure products
- Tier 3 (weight 0.6): Common but narrower audience
- Tier 4 (weight 0.3): Unknown/niche vendors (default)
"""

import re
from typing import Optional

# Minimum length for substring matching - shorter names require exact match
MIN_SUBSTRING_MATCH_LENGTH = 4

# Tier 1: Massive install base - billions of users
TIER_1 = {
    # OS & Platforms
    "MICROSOFT", "APPLE", "GOOGLE", "ANDROID", "LINUX", "UBUNTU", "REDHAT",
    "CENTOS", "DEBIAN", "FEDORA", "SUSE",
    # Cloud
    "AMAZON", "AWS", "AZURE", "GCP", "GOOGLE CLOUD",
    # Browsers
    "CHROME", "FIREFOX", "SAFARI", "EDGE",
    # Mobile
    "IOS", "SAMSUNG",
    # Infrastructure
    "CISCO", "INTEL", "AMD", "NVIDIA",
}

# Tier 2: Enterprise security & infrastructure - IT professionals know these
TIER_2 = {
    # Security vendors
    "FORTINET", "PALO ALTO", "CROWDSTRIKE", "SENTINELONE", "ZSCALER",
    "IVANTI", "CITRIX", "F5", "JUNIPER", "CHECKPOINT", "SOPHOS",
    "TREND MICRO", "MCAFEE", "SYMANTEC", "BROADCOM",
    # Virtualization
    "VMWARE", "NUTANIX", "PROXMOX",
    # Databases
    "ORACLE", "POSTGRESQL", "MYSQL", "MONGODB", "REDIS", "ELASTICSEARCH",
    # Enterprise software
    "SALESFORCE", "SAP", "ATLASSIAN", "SERVICENOW", "SPLUNK",
    "GITLAB", "GITHUB",
}

# Tier 3: Common but narrower audience - developers and specific use cases
TIER_3 = {
    # Web servers & frameworks
    "APACHE", "NGINX", "TOMCAT", "IIS",
    "WORDPRESS", "DRUPAL", "JOOMLA", "MAGENTO",
    "REACT", "ANGULAR", "VUE", "NODE", "NODEJS", "DJANGO", "FLASK", "RAILS",
    # DevOps tools
    "DOCKER", "KUBERNETES", "K8S", "JENKINS", "ANSIBLE", "TERRAFORM",
    "GRAFANA", "PROMETHEUS",
    # Languages/Runtimes
    "PYTHON", "JAVA", "PHP", "RUBY", "GOLANG", "RUST", "DOTNET", ".NET",
    # File transfer (commonly targeted)
    "MOVEIT", "CLEO", "FORTRA", "GOANYWHERE",
}

# Tier weights for score calculation
TIER_WEIGHTS = {
    1: 1.0,   # Full weight - always newsworthy
    2: 0.8,   # High weight - enterprise relevance
    3: 0.6,   # Medium weight - developer/niche relevance
    4: 0.3,   # Low weight - unknown/obscure
}


def _matches_vendor(tier_vendor: str, vendor_upper: str) -> bool:
    """
    Check if a tier vendor matches the input vendor string.

    Uses word-boundary matching to prevent false positives like:
    - "GO" matching "GOOGLE"
    - "SAP" matching "SAPLING"
    - "F5" matching "F500"

    Args:
        tier_vendor: The known vendor name from a tier set (uppercase)
        vendor_upper: The input vendor name (uppercase)

    Returns:
        True if there's a valid match
    """
    # Exact match is always valid
    if tier_vendor == vendor_upper:
        return True

    # For short strings (< MIN_SUBSTRING_MATCH_LENGTH chars),
    # require word boundary matching to avoid false positives.
    # Check BOTH the tier vendor AND the input - either being short
    # can cause false positive substring matches.
    min_len = min(len(tier_vendor), len(vendor_upper))
    if min_len < MIN_SUBSTRING_MATCH_LENGTH:
        # Build regex pattern with word boundaries
        # \b handles word boundaries (spaces, start/end, punctuation)
        pattern = r'\b' + re.escape(tier_vendor) + r'\b'
        if re.search(pattern, vendor_upper):
            return True
        # Also check if input is contained in tier vendor with boundaries
        pattern = r'\b' + re.escape(vendor_upper) + r'\b'
        if re.search(pattern, tier_vendor):
            return True
        return False

    # For longer strings on both sides, substring matching is safe
    if tier_vendor in vendor_upper or vendor_upper in tier_vendor:
        return True

    return False


def get_vendor_tier(vendor: Optional[str]) -> int:
    """
    Determine the tier for a vendor/product name.

    Args:
        vendor: Vendor or product name (case-insensitive)

    Returns:
        Tier number (1-4), where 1 is highest relevance
    """
    if not vendor:
        return 4

    vendor_upper = vendor.upper().strip()

    # Check each tier
    for tier_vendor in TIER_1:
        if _matches_vendor(tier_vendor, vendor_upper):
            return 1

    for tier_vendor in TIER_2:
        if _matches_vendor(tier_vendor, vendor_upper):
            return 2

    for tier_vendor in TIER_3:
        if _matches_vendor(tier_vendor, vendor_upper):
            return 3

    return 4


def get_tier_weight(tier: int) -> float:
    """Get the weight multiplier for a tier."""
    return TIER_WEIGHTS.get(tier, 0.3)

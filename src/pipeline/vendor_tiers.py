"""
Vendor Tier Classification System.

Tiers determine relevance weighting in vulnerability filtering:
- Tier 1 (weight 1.0): Massive install base, affects most viewers
- Tier 2 (weight 0.8): Enterprise security/infrastructure products
- Tier 3 (weight 0.6): Common but narrower audience
- Tier 4 (weight 0.3): Unknown/niche vendors (default)
"""

from typing import Optional

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
    "PYTHON", "JAVA", "PHP", "RUBY", "GO", "RUST", "DOTNET", ".NET",
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
        if tier_vendor in vendor_upper or vendor_upper in tier_vendor:
            return 1

    for tier_vendor in TIER_2:
        if tier_vendor in vendor_upper or vendor_upper in tier_vendor:
            return 2

    for tier_vendor in TIER_3:
        if tier_vendor in vendor_upper or vendor_upper in tier_vendor:
            return 3

    return 4


def get_tier_weight(tier: int) -> float:
    """Get the weight multiplier for a tier."""
    return TIER_WEIGHTS.get(tier, 0.3)

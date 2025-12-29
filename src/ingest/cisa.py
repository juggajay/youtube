"""
CISA KEV (Known Exploited Vulnerabilities) catalog integration.

The KEV catalog lists vulnerabilities that are actively exploited in the wild.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from datetime import datetime
from typing import Dict, Optional, Set

import requests

from ..utils import get_logger

logger = get_logger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache for the KEV catalog
_kev_cache: Optional[Dict[str, dict]] = None
_kev_cache_time: Optional[datetime] = None
_CACHE_TTL_HOURS = 1  # Refresh cache every hour


def fetch_kev_catalog(force_refresh: bool = False) -> Dict[str, dict]:
    """
    Fetch the CISA KEV catalog.

    Results are cached for 1 hour to avoid excessive API calls.

    Args:
        force_refresh: Force a refresh of the cache

    Returns:
        Dictionary mapping CVE ID to KEV entry details
    """
    global _kev_cache, _kev_cache_time

    # Check cache
    if not force_refresh and _kev_cache is not None and _kev_cache_time is not None:
        cache_age = datetime.utcnow() - _kev_cache_time
        if cache_age.total_seconds() < _CACHE_TTL_HOURS * 3600:
            logger.debug("Using cached KEV catalog")
            return _kev_cache

    logger.info("Fetching CISA KEV catalog...")

    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch CISA KEV catalog: {e}")
        return _kev_cache or {}

    # Parse into dictionary keyed by CVE ID
    vulnerabilities = data.get("vulnerabilities", [])
    _kev_cache = {}

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        if cve_id:
            _kev_cache[cve_id] = {
                "cve_id": cve_id,
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "description": vuln.get("shortDescription", ""),
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "required_action": vuln.get("requiredAction", ""),
                "notes": vuln.get("notes", ""),
            }

    _kev_cache_time = datetime.utcnow()
    logger.info(f"Loaded {len(_kev_cache)} CVEs from CISA KEV catalog")

    return _kev_cache


def is_in_kev(cve_id: str) -> bool:
    """
    Check if a CVE is in the CISA KEV catalog.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")

    Returns:
        True if the CVE is in the KEV catalog
    """
    kev_catalog = fetch_kev_catalog()
    return cve_id in kev_catalog


def get_kev_entry(cve_id: str) -> Optional[dict]:
    """
    Get the KEV catalog entry for a CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        KEV entry dict or None if not in catalog
    """
    kev_catalog = fetch_kev_catalog()
    return kev_catalog.get(cve_id)


def get_kev_cve_ids() -> Set[str]:
    """
    Get all CVE IDs in the KEV catalog.

    Returns:
        Set of CVE IDs
    """
    kev_catalog = fetch_kev_catalog()
    return set(kev_catalog.keys())


def enrich_with_kev(cve_id: str) -> dict:
    """
    Get KEV enrichment data for a CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        Dictionary with KEV data (empty if not in KEV)
    """
    entry = get_kev_entry(cve_id)

    if entry:
        return {
            "cisa_kev": True,
            "kev_due_date": entry.get("due_date"),
            "kev_required_action": entry.get("required_action"),
            "exploit_status": "actively_exploited",
        }

    return {
        "cisa_kev": False,
        "kev_due_date": None,
        "kev_required_action": None,
    }

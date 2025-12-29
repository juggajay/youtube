"""
NVD (National Vulnerability Database) API integration.

Fetches recent CVEs from the NVD API v2.0.
https://nvd.nist.gov/developers/vulnerabilities
"""

import time
from datetime import datetime, timedelta
from typing import List, Optional

import requests

from ..utils import get_config, get_logger
from .models import Vulnerability

logger = get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(
    hours: int = 24,
    api_key: Optional[str] = None,
    max_results: int = 100
) -> List[Vulnerability]:
    """
    Fetch CVEs published in the last N hours from NVD.

    Args:
        hours: How many hours back to search (default 24)
        api_key: NVD API key (optional, increases rate limit)
        max_results: Maximum number of results to return

    Returns:
        List of Vulnerability objects
    """
    config = get_config()

    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(hours=hours)

    # Format dates for API
    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info(f"Fetching CVEs from NVD: {pub_start} to {pub_end}")

    # Build request
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": min(max_results, 2000),  # API max is 2000
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        delay = 0.6  # With API key: 50 requests/30 seconds
    else:
        delay = 6  # Without API key: 5 requests/30 seconds

    try:
        response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"NVD API request failed: {e}")
        return []

    # Parse vulnerabilities
    vulnerabilities = []
    cve_items = data.get("vulnerabilities", [])

    logger.info(f"NVD returned {len(cve_items)} CVEs")

    for item in cve_items:
        cve = item.get("cve", {})
        vuln = _parse_nvd_cve(cve)
        if vuln:
            vulnerabilities.append(vuln)

    return vulnerabilities


def _parse_nvd_cve(cve: dict) -> Optional[Vulnerability]:
    """
    Parse a single CVE from NVD API response.

    Args:
        cve: CVE object from NVD API

    Returns:
        Vulnerability object or None if parsing fails
    """
    try:
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Get description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS score (prefer v3.1, fallback to v3.0, then v2)
        cvss_score = 0.0
        cvss_vector = ""

        metrics = cve.get("metrics", {})

        # Try CVSS v3.1
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
        # Fallback to v3.0
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
        # Fallback to v2
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")

        # Extract vendor/product from CPE configurations
        vendor, product, affected_versions = _extract_cpe_info(cve)

        # Get references
        references = []
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        # Find remediation URL (prefer vendor advisories)
        remediation_url = ""
        for ref in cve.get("references", []):
            tags = ref.get("tags", [])
            if "Patch" in tags or "Vendor Advisory" in tags:
                remediation_url = ref.get("url", "")
                break

        # Create title from description (first sentence or first 100 chars)
        title = description.split(".")[0][:100] if description else cve_id

        return Vulnerability(
            cve_id=cve_id,
            title=title,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            vendor=vendor,
            product=product,
            affected_versions=affected_versions,
            remediation_url=remediation_url,
            references=references[:5],  # Limit references
            published_date=cve.get("published"),
            last_modified=cve.get("lastModified"),
            source="NVD",
        )

    except Exception as e:
        logger.warning(f"Failed to parse CVE: {e}")
        return None


def _extract_cpe_info(cve: dict) -> tuple[str, str, str]:
    """
    Extract vendor, product, and version info from CPE configurations.

    Args:
        cve: CVE object from NVD API

    Returns:
        Tuple of (vendor, product, affected_versions)
    """
    vendor = ""
    product = ""
    versions = []

    configurations = cve.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")

                # Parse CPE string: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    if not vendor:
                        vendor = parts[3].replace("_", " ").title()
                    if not product:
                        product = parts[4].replace("_", " ").title()

                    # Collect version info
                    version_start = cpe_match.get("versionStartIncluding", "")
                    version_end = cpe_match.get("versionEndExcluding", "")
                    version_end_incl = cpe_match.get("versionEndIncluding", "")

                    if version_start and version_end:
                        versions.append(f"{version_start} - {version_end}")
                    elif version_start and version_end_incl:
                        versions.append(f"{version_start} - {version_end_incl}")
                    elif version_end:
                        versions.append(f"< {version_end}")

    # Deduplicate and join versions
    affected_versions = ", ".join(list(set(versions))[:3]) if versions else ""

    return vendor, product, affected_versions


def fetch_cve_by_id(cve_id: str, api_key: Optional[str] = None) -> Optional[Vulnerability]:
    """
    Fetch a specific CVE by ID.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        api_key: NVD API key (optional)

    Returns:
        Vulnerability object or None
    """
    logger.info(f"Fetching CVE: {cve_id}")

    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"NVD API request failed: {e}")
        return None

    cve_items = data.get("vulnerabilities", [])
    if not cve_items:
        return None

    return _parse_nvd_cve(cve_items[0].get("cve", {}))

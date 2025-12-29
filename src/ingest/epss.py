"""
EPSS (Exploit Prediction Scoring System) API integration.

EPSS provides probability scores for how likely a vulnerability is to be exploited.
https://www.first.org/epss/
"""

from typing import Dict, List, Optional

import requests

from ..utils import get_logger

logger = get_logger(__name__)

EPSS_API_BASE = "https://api.first.org/data/v1/epss"


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.

    Args:
        cve_ids: List of CVE identifiers

    Returns:
        Dictionary mapping CVE ID to EPSS data (score, percentile)
    """
    if not cve_ids:
        return {}

    logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs")

    results = {}

    # EPSS API accepts up to 100 CVEs per request
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        batch_results = _fetch_epss_batch(batch)
        results.update(batch_results)

    logger.info(f"Retrieved EPSS scores for {len(results)} CVEs")
    return results


def _fetch_epss_batch(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores for a batch of CVE IDs.

    Args:
        cve_ids: List of CVE identifiers (max 100)

    Returns:
        Dictionary mapping CVE ID to EPSS data
    """
    # Join CVE IDs with commas
    cve_param = ",".join(cve_ids)

    try:
        response = requests.get(
            EPSS_API_BASE,
            params={"cve": cve_param},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"EPSS API request failed: {e}")
        return {}

    results = {}
    for item in data.get("data", []):
        cve_id = item.get("cve", "")
        if cve_id:
            results[cve_id] = {
                "epss_score": float(item.get("epss", 0)),
                "epss_percentile": float(item.get("percentile", 0)),
            }

    return results


def fetch_single_epss(cve_id: str) -> Optional[dict]:
    """
    Fetch EPSS score for a single CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        EPSS data dict or None if not found
    """
    results = fetch_epss_scores([cve_id])
    return results.get(cve_id)


def get_high_epss_cves(threshold: float = 0.1) -> List[dict]:
    """
    Fetch CVEs with EPSS score above a threshold.

    Note: This queries the EPSS API for the top scores, not a filtered list.
    The API doesn't support direct filtering, so we'd need to process results.

    Args:
        threshold: Minimum EPSS score (default 0.1 = 10%)

    Returns:
        List of CVE data with high EPSS scores
    """
    logger.info(f"Fetching high EPSS CVEs (threshold: {threshold})")

    try:
        # Get the most recent EPSS data
        response = requests.get(
            EPSS_API_BASE,
            params={
                "order": "!epss",  # Sort by EPSS descending
                "limit": 100,
            },
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        logger.error(f"EPSS API request failed: {e}")
        return []

    # Filter by threshold
    high_epss = []
    for item in data.get("data", []):
        score = float(item.get("epss", 0))
        if score >= threshold:
            high_epss.append({
                "cve_id": item.get("cve", ""),
                "epss_score": score,
                "epss_percentile": float(item.get("percentile", 0)),
            })

    logger.info(f"Found {len(high_epss)} CVEs with EPSS >= {threshold}")
    return high_epss

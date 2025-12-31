"""
Priority Matrix - Filters vulnerabilities BEFORE the LLM sees them.

This is the Source of Truth for vulnerability filtering.
The logic is hardcoded and immutable.

Rules (in order of precedence):
    1. CISA KEV listed -> CRITICAL (always include, actively exploited)
    2. CVSS > 9.0 AND EPSS > 0.10 -> CRITICAL (severe + likely exploited)
    3. CVSS > 7.0 AND EPSS > 0.30 -> HIGH (high severity + high probability)
    4. Everything else -> FILTERED (not included unless manual override)
"""

from typing import List, Tuple

from ..ingest.models import Vulnerability, Priority
from ..utils import get_config, get_logger
from .vendor_tiers import get_vendor_tier, get_tier_weight

logger = get_logger(__name__)

# Minimum content guarantee constants
MIN_VULNERABILITIES = 3
FALLBACK_PRIORITY = Priority.HIGH


def apply_priority_matrix(vuln: Vulnerability) -> Priority:
    """
    Apply the hardcoded Priority Matrix to a vulnerability.

    This logic is IMMUTABLE and runs before any LLM processing.
    The LLM never sees FILTERED vulnerabilities.

    Vendor tier weighting is applied to CVSS scores:
    - Tier 1 (Microsoft, Google, etc.): weight 1.0 (full score)
    - Tier 2 (Fortinet, Palo Alto, etc.): weight 0.8
    - Tier 3 (WordPress, Apache, etc.): weight 0.6
    - Tier 4 (unknown vendors): weight 0.3

    Args:
        vuln: Vulnerability object with scores populated

    Returns:
        Priority enum value
    """
    config = get_config()
    thresholds = config.get("priority_matrix", {})

    critical = thresholds.get("critical", {"cvss_min": 9.0, "epss_min": 0.10})
    high = thresholds.get("high", {"cvss_min": 7.0, "epss_min": 0.30})

    # Rule 1: CISA KEV is always CRITICAL (actively exploited in the wild)
    # This bypasses tier weighting - if it's being exploited, we cover it
    if vuln.cisa_kev:
        vendor_tier = get_vendor_tier(vuln.vendor)
        logger.info(f"{vuln.cve_id}: CRITICAL (CISA KEV listed)")
        _log_filter_decision(vuln, Priority.CRITICAL, "CISA KEV", vendor_tier)
        return Priority.CRITICAL

    # Determine vendor tier - check product name as fallback for tier 4
    vendor_tier = get_vendor_tier(vuln.vendor)
    if vendor_tier == 4 and vuln.product:
        # If vendor is unknown, check if product name contains a known vendor
        product_tier = get_vendor_tier(vuln.product)
        if product_tier < 4:
            vendor_tier = product_tier
            logger.debug(
                f"{vuln.cve_id}: Using product-based tier {vendor_tier} "
                f"(product: {vuln.product})"
            )

    # Calculate effective CVSS with tier weighting
    tier_weight = get_tier_weight(vendor_tier)
    effective_cvss = vuln.cvss_score * tier_weight

    logger.debug(
        f"{vuln.cve_id}: tier={vendor_tier}, weight={tier_weight}, "
        f"raw_cvss={vuln.cvss_score:.1f}, effective_cvss={effective_cvss:.1f}"
    )

    # Rule 2: Very high severity + reasonable exploit probability
    if effective_cvss > critical["cvss_min"] and vuln.epss_score > critical["epss_min"]:
        logger.info(
            f"{vuln.cve_id}: CRITICAL "
            f"(effective CVSS {effective_cvss:.1f} > {critical['cvss_min']} + "
            f"EPSS {vuln.epss_score:.2%} > {critical['epss_min']:.0%}, tier={vendor_tier})"
        )
        _log_filter_decision(vuln, Priority.CRITICAL, "CVSS+EPSS threshold", vendor_tier)
        return Priority.CRITICAL

    # Rule 3: High severity + high exploit probability
    if effective_cvss > high["cvss_min"] and vuln.epss_score > high["epss_min"]:
        logger.info(
            f"{vuln.cve_id}: HIGH "
            f"(effective CVSS {effective_cvss:.1f} > {high['cvss_min']} + "
            f"EPSS {vuln.epss_score:.2%} > {high['epss_min']:.0%}, tier={vendor_tier})"
        )
        _log_filter_decision(vuln, Priority.HIGH, "CVSS+EPSS threshold", vendor_tier)
        return Priority.HIGH

    # Rule 4: Everything else is filtered out
    logger.debug(
        f"{vuln.cve_id}: FILTERED "
        f"(effective CVSS {effective_cvss:.1f}, EPSS {vuln.epss_score:.2%}, tier={vendor_tier})"
    )
    _log_filter_decision(vuln, Priority.FILTERED, "Below thresholds", vendor_tier)
    return Priority.FILTERED


def filter_vulnerabilities(
    vulns: List[Vulnerability],
    min_content: int = MIN_VULNERABILITIES,
) -> Tuple[List[Vulnerability], List[Vulnerability]]:
    """
    Apply Priority Matrix to all vulnerabilities.

    Includes minimum content guarantee: if tier-weighted filtering produces
    fewer than min_content vulnerabilities, backfills from filtered pool
    by raw CVSS score (highest first).

    Args:
        vulns: List of all ingested vulnerabilities
        min_content: Minimum number of vulnerabilities to include (default: 3)

    Returns:
        Tuple of (included, filtered) vulnerability lists
    """
    included = []
    filtered = []

    for vuln in vulns:
        vuln.priority = apply_priority_matrix(vuln)

        if vuln.priority in (Priority.CRITICAL, Priority.HIGH):
            included.append(vuln)
        else:
            filtered.append(vuln)

    # Minimum content guarantee: backfill from filtered pool if needed
    fallback_count = 0
    if len(included) < min_content and filtered:
        # Sort filtered by raw CVSS (highest first) for fallback selection
        filtered.sort(key=lambda v: (-v.cvss_score, -v.epss_score))

        needed = min_content - len(included)
        logger.warning(
            f"FALLBACK TRIGGERED: Only {len(included)} vulns passed tier filtering, "
            f"need {needed} more to meet minimum of {min_content}"
        )

        for vuln in filtered[:needed]:
            # Mark as fallback for analytics/tuning
            vuln._is_fallback = True
            vuln.priority = FALLBACK_PRIORITY
            included.append(vuln)
            fallback_count += 1
            logger.info(
                f"FALLBACK: Including {vuln.cve_id} "
                f"(raw CVSS {vuln.cvss_score:.1f}, vendor={vuln.vendor})"
            )

        # Remove fallback vulns from filtered list
        filtered = filtered[needed:]

    # Sort by priority (CRITICAL first) then by CVSS score descending
    included.sort(key=lambda v: (
        0 if v.priority == Priority.CRITICAL else 1,
        -v.cvss_score,
        -v.epss_score,
    ))

    logger.info(
        f"Priority Matrix: {len(included)} included "
        f"({sum(1 for v in included if v.priority == Priority.CRITICAL)} critical, "
        f"{sum(1 for v in included if v.priority == Priority.HIGH)} high"
        f"{f', {fallback_count} fallback' if fallback_count else ''}), "
        f"{len(filtered)} filtered out"
    )

    return included, filtered


def _log_filter_decision(
    vuln: Vulnerability,
    priority: Priority,
    reason: str,
    vendor_tier: int = 4,
) -> None:
    """
    Log filter decision for analytics.

    These logs can be analyzed to tune thresholds if too many episodes are nuked.

    Args:
        vuln: The vulnerability being evaluated
        priority: The resulting priority level
        reason: Human-readable reason for the decision
        vendor_tier: The vendor tier (1-4) used in weighting
    """
    tier_weight = get_tier_weight(vendor_tier)
    effective_cvss = vuln.cvss_score * tier_weight

    logger.debug(
        f"FILTER_DECISION | "
        f"cve={vuln.cve_id} | "
        f"cvss={vuln.cvss_score:.1f} | "
        f"effective_cvss={effective_cvss:.1f} | "
        f"tier={vendor_tier} | "
        f"epss={vuln.epss_score:.4f} | "
        f"kev={vuln.cisa_kev} | "
        f"result={priority.value} | "
        f"reason={reason}"
    )


def check_manual_override(cve_id: str, overrides: dict) -> Priority:
    """
    Check if a CVE has a manual override.

    Allows editor to force-include a filtered vulnerability or
    force-exclude a normally included one via Airtable.

    Args:
        cve_id: The CVE identifier
        overrides: Dict of {cve_id: priority_override} from Airtable

    Returns:
        Priority override if exists, None otherwise
    """
    if cve_id in overrides:
        override_value = overrides[cve_id]
        try:
            priority = Priority(override_value)
            logger.info(f"{cve_id}: MANUAL OVERRIDE -> {priority.value}")
            return priority
        except ValueError:
            logger.warning(f"Invalid override value for {cve_id}: {override_value}")

    return None


def create_daily_brief_packet(
    included: List[Vulnerability],
    filtered: List[Vulnerability],
    episode_date: str,
) -> dict:
    """
    Create the daily_brief_packet.json structure.

    Args:
        included: Vulnerabilities that passed the Priority Matrix
        filtered: Vulnerabilities that were filtered out
        episode_date: Date string (YYYY-MM-DD)

    Returns:
        Dictionary ready for JSON serialization
    """
    from datetime import datetime

    return {
        "date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "filter_stats": {
            "total_ingested": len(included) + len(filtered),
            "critical_count": sum(1 for v in included if v.priority == Priority.CRITICAL),
            "high_count": sum(1 for v in included if v.priority == Priority.HIGH),
            "filtered_count": len(filtered),
        },
        "vulnerabilities": [v.to_dict() for v in included],
        "filtered_vulnerabilities": [
            {"cve_id": v.cve_id, "cvss_score": v.cvss_score, "epss_score": v.epss_score}
            for v in filtered[:20]  # Keep top 20 filtered for debugging
        ],
    }

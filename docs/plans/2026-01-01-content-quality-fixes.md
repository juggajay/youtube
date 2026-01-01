# Content Quality Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 7 content quality issues that damage channel credibility by implementing vendor relevance weighting, CVE year context, improved validation, story impact scoring, thumbnail alignment, AI disclosure, and reduced episode density.

**Architecture:** Modular changes across the pipeline - each fix is independent and can be tested in isolation. Changes flow: filter_score.py (vendor tiers) → orchestrator.py (story selection) → generate_script.py (CVE context + disclosure) → script_validator.py (narrowed LLM scope) → thumbnail_generator.py (story alignment).

**Tech Stack:** Python 3.12, pytest, dataclasses, existing Gemini LLM integration

---

## Prerequisites

Before starting, create the test infrastructure:

### Task 0: Set Up Test Infrastructure

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `pytest.ini`

**Step 1: Create test directory and pytest config**

```python
# tests/__init__.py
# Test package
```

```python
# tests/conftest.py
"""Shared test fixtures for the podcast pipeline."""

import pytest
from datetime import datetime
from src.ingest.models import Vulnerability, Story, Priority, StoryType


@pytest.fixture
def sample_tier1_vuln():
    """Microsoft vulnerability - should always pass filter."""
    return Vulnerability(
        cve_id="CVE-2025-0001",
        title="Microsoft Exchange RCE",
        description="Remote code execution in Microsoft Exchange Server",
        cvss_score=9.8,
        epss_score=0.45,
        cisa_kev=False,
        vendor="Microsoft",
        product="Exchange Server",
        affected_versions="2019, 2016",
    )


@pytest.fixture
def sample_tier4_vuln():
    """Obscure vendor - should be filtered unless very severe."""
    return Vulnerability(
        cve_id="CVE-2025-0002",
        title="Akuvox Intercom Vulnerability",
        description="Authentication bypass in Akuvox S539 intercom",
        cvss_score=9.5,
        epss_score=0.15,
        cisa_kev=False,
        vendor="Akuvox",
        product="S539 Smart Intercom",
        affected_versions="1.0 - 2.5",
    )


@pytest.fixture
def sample_kev_vuln():
    """CISA KEV listed - should always pass regardless of vendor."""
    return Vulnerability(
        cve_id="CVE-2025-0003",
        title="TinyControl LAN Controller Exploit",
        description="Actively exploited vulnerability",
        cvss_score=7.5,
        epss_score=0.08,
        cisa_kev=True,
        vendor="TinyControl",
        product="LAN Controller",
        affected_versions="1.0",
    )


@pytest.fixture
def sample_high_impact_story():
    """Story with high impact indicators."""
    return Story(
        id="story-001",
        title="Trust Wallet Loses $8.5 Million in Security Breach",
        summary="Millions of cryptocurrency users affected by wallet vulnerability",
        url="https://example.com/trust-wallet",
        story_type=StoryType.BREACH,
        impact_score=90.0,
        recency_score=80.0,
        buzz_score=70.0,
        final_score=80.0,
        source_name="BleepingComputer",
    )


@pytest.fixture
def sample_low_impact_story():
    """Story with low impact indicators."""
    return Story(
        id="story-002",
        title="Romanian Energy Company Hit by Ransomware",
        summary="Small regional utility experiences outage",
        url="https://example.com/romania-energy",
        story_type=StoryType.RANSOMWARE,
        impact_score=30.0,
        recency_score=80.0,
        buzz_score=20.0,
        final_score=40.0,
        source_name="The Record",
    )


@pytest.fixture
def sample_daily_brief():
    """Sample daily brief packet for testing."""
    return {
        "date": "2025-01-01",
        "vulnerabilities": [],
        "filter_stats": {
            "total_ingested": 50,
            "critical_count": 3,
            "high_count": 5,
            "filtered_count": 42,
        },
    }
```

```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -v --tb=short
```

**Step 2: Run pytest to verify setup**

Run: `pytest --collect-only`
Expected: "no tests collected" (but no errors)

**Step 3: Commit**

```bash
git add tests/ pytest.ini
git commit -m "chore: add pytest infrastructure for TDD"
```

---

## Issue 1: Vendor Relevance Tiering

**Priority:** CRITICAL - Root cause of most content quality issues

### Task 1.1: Define Vendor Tier Constants

**Files:**
- Create: `src/pipeline/vendor_tiers.py`
- Create: `tests/test_vendor_tiers.py`

**Step 1: Write the failing test**

```python
# tests/test_vendor_tiers.py
"""Tests for vendor tier classification."""

import pytest
from src.pipeline.vendor_tiers import get_vendor_tier, TIER_1, TIER_2, TIER_3


class TestGetVendorTier:
    """Test vendor tier classification."""

    def test_microsoft_is_tier_1(self):
        assert get_vendor_tier("Microsoft") == 1
        assert get_vendor_tier("MICROSOFT") == 1
        assert get_vendor_tier("microsoft") == 1

    def test_aws_is_tier_1(self):
        assert get_vendor_tier("Amazon") == 1
        assert get_vendor_tier("AWS") == 1

    def test_fortinet_is_tier_2(self):
        assert get_vendor_tier("Fortinet") == 2
        assert get_vendor_tier("Palo Alto") == 2
        assert get_vendor_tier("Ivanti") == 2

    def test_wordpress_is_tier_3(self):
        assert get_vendor_tier("WordPress") == 3
        assert get_vendor_tier("Apache") == 3
        assert get_vendor_tier("React") == 3

    def test_unknown_vendor_is_tier_4(self):
        assert get_vendor_tier("Akuvox") == 4
        assert get_vendor_tier("TinyControl") == 4
        assert get_vendor_tier("RandomVendor123") == 4

    def test_empty_vendor_is_tier_4(self):
        assert get_vendor_tier("") == 4
        assert get_vendor_tier(None) == 4
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_vendor_tiers.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'src.pipeline.vendor_tiers'"

**Step 3: Write minimal implementation**

```python
# src/pipeline/vendor_tiers.py
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_vendor_tiers.py -v`
Expected: PASS (6 tests)

**Step 5: Commit**

```bash
git add src/pipeline/vendor_tiers.py tests/test_vendor_tiers.py
git commit -m "feat: add vendor tier classification system"
```

---

### Task 1.2: Integrate Vendor Tiers into Priority Matrix

**Files:**
- Modify: `src/pipeline/filter_score.py:22-73`
- Create: `tests/test_filter_score.py`

**Step 1: Write the failing test**

```python
# tests/test_filter_score.py
"""Tests for priority matrix with vendor tiering."""

import pytest
from src.pipeline.filter_score import apply_priority_matrix
from src.ingest.models import Vulnerability, Priority


class TestVendorTieredFiltering:
    """Test that vendor tier affects filtering decisions."""

    def test_tier1_moderate_severity_passes(self):
        """Microsoft CVSS 8.0 should pass (tier 1 boost)."""
        vuln = Vulnerability(
            cve_id="CVE-2025-1001",
            cvss_score=8.0,
            epss_score=0.15,
            vendor="Microsoft",
            product="Exchange",
            cisa_kev=False,
        )
        priority = apply_priority_matrix(vuln)
        assert priority in (Priority.CRITICAL, Priority.HIGH)

    def test_tier4_high_severity_filtered(self):
        """Unknown vendor CVSS 9.0 should be filtered (tier 4 penalty)."""
        vuln = Vulnerability(
            cve_id="CVE-2025-1002",
            cvss_score=9.0,
            epss_score=0.12,
            vendor="Akuvox",
            product="S539",
            cisa_kev=False,
        )
        priority = apply_priority_matrix(vuln)
        # With tier 4 weight (0.3), effective CVSS is 9.0 * 0.3 = 2.7
        # Should not meet CRITICAL threshold
        assert priority == Priority.FILTERED

    def test_kev_always_passes_regardless_of_tier(self):
        """CISA KEV should always be CRITICAL, even for unknown vendors."""
        vuln = Vulnerability(
            cve_id="CVE-2025-1003",
            cvss_score=7.0,
            epss_score=0.05,
            vendor="TinyControl",
            product="LAN Controller",
            cisa_kev=True,
        )
        priority = apply_priority_matrix(vuln)
        assert priority == Priority.CRITICAL

    def test_tier2_enterprise_vendor_passes_high(self):
        """Fortinet CVSS 8.5 should pass as HIGH."""
        vuln = Vulnerability(
            cve_id="CVE-2025-1004",
            cvss_score=8.5,
            epss_score=0.25,
            vendor="Fortinet",
            product="FortiGate",
            cisa_kev=False,
        )
        priority = apply_priority_matrix(vuln)
        assert priority in (Priority.CRITICAL, Priority.HIGH)

    def test_filter_decision_logs_vendor_tier(self, caplog):
        """Verify filtering logs include vendor tier information."""
        import logging
        caplog.set_level(logging.DEBUG)

        vuln = Vulnerability(
            cve_id="CVE-2025-1005",
            cvss_score=9.5,
            epss_score=0.20,
            vendor="Microsoft",
            product="Windows",
            cisa_kev=False,
        )
        apply_priority_matrix(vuln)

        # Check that tier was logged
        assert any("tier=1" in record.message.lower() or "tier 1" in record.message.lower()
                   for record in caplog.records)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_filter_score.py -v`
Expected: FAIL (tests expect tier-aware behavior that doesn't exist yet)

**Step 3: Modify filter_score.py implementation**

```python
# In src/pipeline/filter_score.py, replace apply_priority_matrix function:

from .vendor_tiers import get_vendor_tier, get_tier_weight

def apply_priority_matrix(vuln: Vulnerability) -> Priority:
    """
    Apply the Priority Matrix with vendor tier weighting.

    The effective score is calculated as:
        effective_cvss = cvss_score * tier_weight

    This ensures Tier 1 vendors (Microsoft, Apple, etc.) pass with lower
    raw scores, while obscure vendors need significantly higher severity.

    CISA KEV is always CRITICAL regardless of vendor tier.

    Args:
        vuln: Vulnerability object with scores populated

    Returns:
        Priority enum value
    """
    config = get_config()
    thresholds = config.get("priority_matrix", {})

    critical = thresholds.get("critical", {"cvss_min": 9.0, "epss_min": 0.10})
    high = thresholds.get("high", {"cvss_min": 7.0, "epss_min": 0.30})

    # Determine vendor tier and weight
    vendor_tier = get_vendor_tier(vuln.vendor)
    if vendor_tier == 4:
        # Also check product name for tier matches
        product_tier = get_vendor_tier(vuln.product)
        vendor_tier = min(vendor_tier, product_tier)

    tier_weight = get_tier_weight(vendor_tier)

    # Rule 1: CISA KEV is always CRITICAL (actively exploited in the wild)
    # This rule is ABSOLUTE - vendor tier does not affect it
    if vuln.cisa_kev:
        logger.info(f"{vuln.cve_id}: CRITICAL (CISA KEV listed) [tier={vendor_tier}]")
        _log_filter_decision(vuln, Priority.CRITICAL, "CISA KEV", vendor_tier)
        return Priority.CRITICAL

    # Calculate effective scores with tier weighting
    effective_cvss = vuln.cvss_score * tier_weight
    effective_epss = vuln.epss_score  # EPSS not weighted (exploit probability is absolute)

    # Rule 2: Very high effective severity + reasonable exploit probability
    if effective_cvss > critical["cvss_min"] and effective_epss > critical["epss_min"]:
        logger.info(
            f"{vuln.cve_id}: CRITICAL "
            f"(effective CVSS {effective_cvss:.1f} [{vuln.cvss_score:.1f} * {tier_weight}] > {critical['cvss_min']} + "
            f"EPSS {vuln.epss_score:.2%} > {critical['epss_min']:.0%}) [tier={vendor_tier}]"
        )
        _log_filter_decision(vuln, Priority.CRITICAL, "CVSS+EPSS threshold", vendor_tier)
        return Priority.CRITICAL

    # Rule 3: High effective severity + high exploit probability
    if effective_cvss > high["cvss_min"] and effective_epss > high["epss_min"]:
        logger.info(
            f"{vuln.cve_id}: HIGH "
            f"(effective CVSS {effective_cvss:.1f} [{vuln.cvss_score:.1f} * {tier_weight}] > {high['cvss_min']} + "
            f"EPSS {vuln.epss_score:.2%} > {high['epss_min']:.0%}) [tier={vendor_tier}]"
        )
        _log_filter_decision(vuln, Priority.HIGH, "CVSS+EPSS threshold", vendor_tier)
        return Priority.HIGH

    # Rule 4: Everything else is filtered out
    logger.debug(
        f"{vuln.cve_id}: FILTERED "
        f"(effective CVSS {effective_cvss:.1f} [{vuln.cvss_score:.1f} * {tier_weight}], "
        f"EPSS {vuln.epss_score:.2%}) [tier={vendor_tier}]"
    )
    _log_filter_decision(vuln, Priority.FILTERED, "Below thresholds", vendor_tier)
    return Priority.FILTERED


def _log_filter_decision(vuln: Vulnerability, priority: Priority, reason: str, vendor_tier: int = 4) -> None:
    """
    Log filter decision for analytics.

    These logs can be analyzed to tune thresholds if too many episodes are nuked.
    Now includes vendor tier for relevance analysis.
    """
    tier_weight = get_tier_weight(vendor_tier)
    effective_cvss = vuln.cvss_score * tier_weight

    logger.debug(
        f"FILTER_DECISION | "
        f"cve={vuln.cve_id} | "
        f"vendor={vuln.vendor} | "
        f"tier={vendor_tier} | "
        f"weight={tier_weight} | "
        f"cvss={vuln.cvss_score:.1f} | "
        f"effective_cvss={effective_cvss:.1f} | "
        f"epss={vuln.epss_score:.4f} | "
        f"kev={vuln.cisa_kev} | "
        f"result={priority.value} | "
        f"reason={reason}"
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_filter_score.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add src/pipeline/filter_score.py tests/test_filter_score.py
git commit -m "feat: integrate vendor tier weighting into priority matrix"
```

---

### Task 1.3: Add Minimum Content Guarantee

**Problem:** Tier 4 vendor with CVSS 9.5 gets effective score of 2.85 (9.5 × 0.3), which never passes thresholds. This could result in empty episodes on quiet days.

**Solution:** After tier-weighted filter, check if minimum content is met. If not, progressively backfill from filtered pool by raw CVSS.

**Files:**
- Modify: `src/pipeline/filter_score.py`
- Extend: `tests/test_filter_score.py`

**Step 1: Write the failing test**

```python
# Add to tests/test_filter_score.py

class TestMinimumContentGuarantee:
    """Test that filter ensures minimum content for episodes."""

    def test_minimum_3_vulns_when_only_tier4(self):
        """Even if all vulns are Tier 4, should include top 3 by raw CVSS."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        # Create 5 Tier-4 vulns that would normally all be filtered
        vulns = [
            Vulnerability(cve_id=f"CVE-2025-000{i}", cvss_score=9.5 - (i * 0.1),
                         epss_score=0.15, vendor="Akuvox", product=f"Product{i}")
            for i in range(5)
        ]

        included, filtered = filter_vulnerabilities(vulns)

        # Should have at least 3 despite tier weighting
        assert len(included) >= 3

    def test_fallback_vulns_marked_in_logs(self, caplog):
        """Fallback vulns should be logged for tuning."""
        import logging
        caplog.set_level(logging.INFO)

        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        vulns = [
            Vulnerability(cve_id="CVE-2025-0001", cvss_score=9.5,
                         epss_score=0.15, vendor="UnknownVendor", product="Thing")
        ]

        filter_vulnerabilities(vulns)

        # Should log fallback trigger
        assert any("fallback" in record.message.lower() for record in caplog.records)

    def test_no_fallback_when_enough_content(self):
        """No fallback needed when tier filtering produces enough content."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        # Create 5 Tier-1 vulns that will pass normally
        vulns = [
            Vulnerability(cve_id=f"CVE-2025-000{i}", cvss_score=9.5,
                         epss_score=0.15, vendor="Microsoft", product="Exchange")
            for i in range(5)
        ]

        included, filtered = filter_vulnerabilities(vulns)

        # All should pass without fallback
        assert len(included) == 5

    def test_kev_counts_toward_minimum(self):
        """KEV vulns should count toward minimum content."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        vulns = [
            # 2 KEV vulns (always pass)
            Vulnerability(cve_id="CVE-2025-0001", cvss_score=7.0,
                         epss_score=0.05, vendor="TinyVendor", cisa_kev=True),
            Vulnerability(cve_id="CVE-2025-0002", cvss_score=7.5,
                         epss_score=0.05, vendor="SmallCo", cisa_kev=True),
            # 1 Tier-4 that would be filtered
            Vulnerability(cve_id="CVE-2025-0003", cvss_score=9.0,
                         epss_score=0.15, vendor="Unknown", cisa_kev=False),
        ]

        included, filtered = filter_vulnerabilities(vulns)

        # 2 KEV + 1 fallback = 3 minimum
        assert len(included) >= 3
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_filter_score.py::TestMinimumContentGuarantee -v`
Expected: FAIL (no minimum content logic exists)

**Step 3: Update filter_vulnerabilities with minimum content guarantee**

```python
# In src/pipeline/filter_score.py, update filter_vulnerabilities function:

# Configuration constants
MIN_VULNERABILITIES = 3  # Minimum vulns for a viable episode
FALLBACK_PRIORITY = Priority.HIGH  # Priority assigned to fallback vulns


def filter_vulnerabilities(
    vulns: List[Vulnerability],
    min_content: int = MIN_VULNERABILITIES,
) -> Tuple[List[Vulnerability], List[Vulnerability]]:
    """
    Apply Priority Matrix to all vulnerabilities with minimum content guarantee.

    Two-pass approach:
    1. Quality pass: Apply tier-weighted filtering
    2. Fallback pass: If below minimum, backfill from filtered pool by raw CVSS

    Args:
        vulns: List of all ingested vulnerabilities
        min_content: Minimum vulnerabilities for viable episode (default: 3)

    Returns:
        Tuple of (included, filtered) vulnerability lists
    """
    included = []
    filtered = []

    # Pass 1: Quality filter with tier weighting
    for vuln in vulns:
        vuln.priority = apply_priority_matrix(vuln)

        if vuln.priority in (Priority.CRITICAL, Priority.HIGH):
            included.append(vuln)
        else:
            filtered.append(vuln)

    # Pass 2: Minimum content guarantee
    if len(included) < min_content and filtered:
        shortfall = min_content - len(included)

        # Sort filtered by raw CVSS (ignore tier for fallback)
        filtered.sort(key=lambda v: (-v.cvss_score, -v.epss_score))

        # Take top N from filtered pool
        fallback_vulns = filtered[:shortfall]

        for vuln in fallback_vulns:
            logger.info(
                f"{vuln.cve_id}: FALLBACK inclusion "
                f"(raw CVSS {vuln.cvss_score:.1f}, tier-filtered but needed for minimum content)"
            )
            vuln.priority = FALLBACK_PRIORITY
            vuln._is_fallback = True  # Mark for analytics
            _log_filter_decision(vuln, FALLBACK_PRIORITY, "Fallback for minimum content",
                                get_vendor_tier(vuln.vendor))
            included.append(vuln)

        # Remove fallback vulns from filtered list
        filtered = filtered[shortfall:]

        logger.warning(
            f"FALLBACK TRIGGERED: Added {len(fallback_vulns)} vulns to meet minimum of {min_content}. "
            f"Consider tuning tier weights if this happens frequently."
        )

    # Sort by priority (CRITICAL first) then by CVSS score descending
    included.sort(key=lambda v: (
        0 if v.priority == Priority.CRITICAL else 1,
        -v.cvss_score,
        -v.epss_score,
    ))

    logger.info(
        f"Priority Matrix: {len(included)} included "
        f"({sum(1 for v in included if v.priority == Priority.CRITICAL)} critical, "
        f"{sum(1 for v in included if v.priority == Priority.HIGH)} high), "
        f"{len(filtered)} filtered out"
    )

    return included, filtered
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_filter_score.py::TestMinimumContentGuarantee -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add src/pipeline/filter_score.py tests/test_filter_score.py
git commit -m "feat: add minimum content guarantee with fallback mechanism"
```

---

## Issue 2: CVE Year Context in Scripts

**Priority:** HIGH - Quick win for viewer understanding

### Task 2.1: Add CVE Year Handling to System Prompt

**Files:**
- Modify: `src/pipeline/generate_script.py:263-400` (SYSTEM_PROMPT)
- Create: `tests/test_generate_script.py`

**Step 1: Write the failing test**

```python
# tests/test_generate_script.py
"""Tests for script generation."""

import pytest
from datetime import datetime
from src.pipeline.generate_script import SYSTEM_PROMPT


class TestSystemPromptContent:
    """Test that system prompt contains required instructions."""

    def test_prompt_includes_cve_year_context_instructions(self):
        """Prompt should instruct LLM to explain old CVE years."""
        assert "year" in SYSTEM_PROMPT.lower()
        # Should mention handling old CVE years
        assert any(phrase in SYSTEM_PROMPT.lower() for phrase in [
            "old-looking year",
            "year discrepancy",
            "backdated",
            "just hit the nvd",
            "disclosure queue",
        ])

    def test_prompt_includes_example_year_explanations(self):
        """Prompt should provide example phrases for year context."""
        # Should have natural phrasing examples
        assert any(phrase in SYSTEM_PROMPT for phrase in [
            "2022 ID",
            "just hit the NVD",
            "disclosure queue",
            "fresh intel",
        ])
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_generate_script.py::TestSystemPromptContent -v`
Expected: FAIL (prompt doesn't yet contain year context instructions)

**Step 3: Add CVE year context section to SYSTEM_PROMPT**

In `src/pipeline/generate_script.py`, add after the GROUNDING RULES section (around line 280):

```python
# Add this section to SYSTEM_PROMPT after "## CRITICAL GROUNDING RULES":

## CVE YEAR CONTEXT (IMPORTANT)

When a CVE year doesn't match the current year, explain why it's news now.

**The Problem:** NVD assigns CVE IDs when first reported, which can be years before public disclosure. Viewers hear "CVE-2022-50794" and think it's old news.

**The Fix:** Briefly acknowledge and explain. Make it conversational, not technical.

**Example phrases (use naturally, vary them):**
- "CVE-2022-50794 - and yes, that's a 2022 ID, but it just hit the NVD database yesterday"
- "This one's been in the disclosure queue for a while - vendors sometimes take years to coordinate patches before going public"
- "Don't let the 2022 date fool you - this is fresh intel, just published"
- Melody: "Another backdated one, huh?" (can be a character trait)

**Rules:**
- Only explain if CVE year is 2+ years before current date
- One brief mention per CVE - don't belabor it
- Current/last year CVEs need no explanation
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_generate_script.py::TestSystemPromptContent -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add src/pipeline/generate_script.py tests/test_generate_script.py
git commit -m "feat: add CVE year context instructions to script prompt"
```

---

## Issue 3: Re-enable LLM Validation with Narrowed Scope

**Priority:** HIGH - Catches errors before they go live

### Task 3.1: Create Focused LLM Validation Prompt

**Files:**
- Modify: `src/pipeline/script_validator.py:387-418`
- Add new function for source-grounded validation
- Create: `tests/test_script_validator.py`

**Step 1: Write the failing test**

```python
# tests/test_script_validator.py
"""Tests for script validation."""

import pytest
from src.pipeline.script_validator import (
    cross_check_cves,
    run_rule_based_validation,
    LLM_VALIDATION_PROMPT_V2,
)


class TestCVECrossCheck:
    """Test CVE cross-checking against input data."""

    def test_detects_hallucinated_cve(self):
        """Script CVE not in input should be flagged."""
        script = {
            "dialogue": [
                {"speaker": "Alec", "text": "CVE-2025-99999 is critical."},
            ]
        }
        input_data = {
            "vulnerabilities": [
                {"cve_id": "CVE-2025-0001"},
            ],
            "stories": [],
        }
        issues = cross_check_cves(script, input_data)
        assert len(issues) == 1
        assert issues[0]["type"] == "hallucinated_cve"
        assert issues[0]["severity"] == "critical"

    def test_valid_cve_not_flagged(self):
        """Script CVE in input should not be flagged."""
        script = {
            "dialogue": [
                {"speaker": "Alec", "text": "CVE-2025-0001 affects Exchange."},
            ]
        }
        input_data = {
            "vulnerabilities": [
                {"cve_id": "CVE-2025-0001"},
            ],
            "stories": [],
        }
        issues = cross_check_cves(script, input_data)
        assert len(issues) == 0


class TestLLMValidationPromptV2:
    """Test that new LLM validation prompt is properly scoped."""

    def test_prompt_focuses_on_input_verification(self):
        """Prompt should verify against input data only."""
        assert "input data" in LLM_VALIDATION_PROMPT_V2.lower()
        assert "source data" in LLM_VALIDATION_PROMPT_V2.lower()

    def test_prompt_excludes_product_name_checking(self):
        """Prompt should NOT check if products are 'real'."""
        prompt_lower = LLM_VALIDATION_PROMPT_V2.lower()
        assert "do not flag" in prompt_lower or "should not check" in prompt_lower
        # Should explicitly exclude product name validation
        assert "product names" in prompt_lower

    def test_prompt_checks_cve_against_source(self):
        """Prompt should verify CVEs against source."""
        assert "CVE" in LLM_VALIDATION_PROMPT_V2
        assert any(phrase in LLM_VALIDATION_PROMPT_V2 for phrase in [
            "appear in the source",
            "exist in the input",
            "match the source",
        ])
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_script_validator.py -v`
Expected: FAIL (LLM_VALIDATION_PROMPT_V2 doesn't exist)

**Step 3: Add the new focused validation prompt**

In `src/pipeline/script_validator.py`, add after line 418:

```python
# New focused validation prompt that only checks against source data
LLM_VALIDATION_PROMPT_V2 = """You are a fact-checker verifying a cybersecurity podcast script against its source data.

## YOUR ONLY JOB
Verify that claims in the script match the provided SOURCE DATA. You are NOT a security expert - trust the source data as authoritative.

## SOURCE DATA PROVIDED
You will receive:
1. Vulnerability data (CVE IDs, vendors, products, CVSS scores)
2. Story data (headlines, summaries, company names, researcher names)

## WHAT TO CHECK (flag as issues)
1. **CVE IDs** - Flag if script mentions CVE-XXXX-YYYYY that does NOT appear in source data
2. **Statistics** - Flag specific numbers ($8.5 million, 2 million users) that don't appear in source data
3. **CISA KEV status** - Flag if script claims "actively exploited" but source shows cisa_kev=false
4. **Names** - Flag researcher/person names that don't appear in source data

## WHAT NOT TO CHECK (ignore these)
1. **Product names** - If source says "Akuvox S539", trust it's real. Don't flag unfamiliar products.
2. **Company names** - Source data is authoritative. Don't flag because you haven't heard of a company.
3. **Technical accuracy** - Don't verify if the vulnerability description is technically correct.
4. **Writing quality** - Don't flag style issues, just factual mismatches.

## SEVERITY LEVELS
- **critical**: CVE ID in script not found in source data (definite hallucination)
- **high**: Statistics/claims that directly contradict source data
- **medium**: Names or attributions not verifiable against source (may be ok if general)

## OUTPUT FORMAT (JSON only)
{
  "issues_found": true/false,
  "issues": [
    {
      "type": "hallucinated_cve|wrong_statistic|false_claim|unverified_name",
      "severity": "critical|high|medium",
      "script_excerpt": "the problematic text from script",
      "explanation": "why this doesn't match source data",
      "source_check": "what you looked for in source data"
    }
  ],
  "summary": "Brief summary of findings"
}

## SOURCE DATA
{source_data}

## SCRIPT TO VERIFY
{script_text}
"""
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_script_validator.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add src/pipeline/script_validator.py tests/test_script_validator.py
git commit -m "feat: add focused LLM validation prompt for source-grounded checking"
```

---

### Task 3.2: Re-enable LLM Validation in Orchestrator

**Files:**
- Modify: `src/orchestrator.py:260-267`

**Step 1: Write the failing test**

```python
# tests/test_orchestrator.py
"""Tests for orchestrator pipeline."""

import pytest
from unittest.mock import patch, MagicMock

class TestValidationStep:
    """Test script validation step."""

    def test_llm_validation_is_enabled(self):
        """LLM validation should be enabled with V2 prompt."""
        # Read the orchestrator source to check the use_llm parameter
        with open("src/orchestrator.py") as f:
            source = f.read()

        # Find the validate_and_fix call
        assert "use_llm=True" in source or "use_llm=False" not in source.split("validate_and_fix")[1].split(")")[0]
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_orchestrator.py::TestValidationStep -v`
Expected: FAIL (orchestrator has use_llm=False)

**Step 3: Re-enable LLM validation**

In `src/orchestrator.py`, change line 266-267:

```python
# Change from:
use_llm=False  # Disabled - LLM doesn't have CVE context

# To:
use_llm=True  # Re-enabled with V2 prompt that only checks against source data
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py::TestValidationStep -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: re-enable LLM validation with source-grounded V2 prompt"
```

---

## Issue 4: Story Impact Weighting

**Priority:** MEDIUM - Ensures best content gets featured

### Task 4.1: Add Impact Scoring Function

**Files:**
- Create: `src/ingest/story_scoring.py`
- Create: `tests/test_story_scoring.py`

**Step 1: Write the failing test**

```python
# tests/test_story_scoring.py
"""Tests for story impact scoring."""

import pytest
from src.ingest.story_scoring import calculate_impact_score
from src.ingest.models import Story, StoryType


class TestImpactScoring:
    """Test story impact score calculation."""

    def test_high_dollar_amount_boosts_score(self):
        """Stories with millions in damages should score high."""
        story = Story(
            id="test-1",
            title="Trust Wallet Loses $8.5 Million",
            summary="Millions of cryptocurrency users affected",
            story_type=StoryType.BREACH,
        )
        score = calculate_impact_score(story)
        assert score >= 80  # High impact

    def test_millions_of_users_boosts_score(self):
        """Stories affecting millions of users should score high."""
        story = Story(
            id="test-2",
            title="Security Flaw in Popular App",
            summary="Over 50 million users potentially exposed",
            story_type=StoryType.BREACH,
        )
        score = calculate_impact_score(story)
        assert score >= 70

    def test_tier1_vendor_boosts_score(self):
        """Stories mentioning Tier 1 vendors should score higher."""
        story = Story(
            id="test-3",
            title="Microsoft Patches Critical Flaw",
            summary="Windows users urged to update immediately",
            story_type=StoryType.VULNERABILITY,
        )
        score = calculate_impact_score(story)
        assert score >= 60

    def test_nation_state_attribution_boosts_score(self):
        """APT/nation-state stories should score high."""
        story = Story(
            id="test-4",
            title="China-linked APT Group Targets US Infrastructure",
            summary="Volt Typhoon campaign continues",
            story_type=StoryType.APT,
        )
        score = calculate_impact_score(story)
        assert score >= 75

    def test_small_regional_story_scores_low(self):
        """Small regional stories without scale indicators should score low."""
        story = Story(
            id="test-5",
            title="Romanian Energy Company Hit by Ransomware",
            summary="Oltenia electricity provider experiences brief outage",
            story_type=StoryType.RANSOMWARE,
        )
        score = calculate_impact_score(story)
        assert score <= 50
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_story_scoring.py -v`
Expected: FAIL with ModuleNotFoundError

**Step 3: Implement impact scoring**

```python
# src/ingest/story_scoring.py
"""
Story Impact Scoring.

Calculates relevance scores for news stories based on impact indicators.
"""

import re
from typing import List

from .models import Story, StoryType
from ..pipeline.vendor_tiers import TIER_1, TIER_2


def calculate_impact_score(story: Story) -> float:
    """
    Calculate impact score based on story indicators.

    Factors:
    - Dollar amounts (millions/billions)
    - User counts (millions affected)
    - Tier 1/2 vendor mentions
    - Nation-state/APT attribution
    - Supply chain implications
    - Government/critical infrastructure

    Returns:
        Score 0-100
    """
    score = 0.0
    text = f"{story.title} {story.summary}".upper()

    # Dollar amounts (millions+)
    money_patterns = [
        (r'\$\d+(?:\.\d+)?\s*(?:MILLION|M\b)', 30),   # $X million
        (r'\$\d+(?:\.\d+)?\s*(?:BILLION|B\b)', 50),   # $X billion
        (r'MILLIONS?\s+(?:OF\s+)?(?:DOLLARS|USD)', 25),
    ]
    for pattern, points in money_patterns:
        if re.search(pattern, text):
            score += points
            break  # Only count once

    # User counts
    user_patterns = [
        (r'(?:MILLIONS?\s+(?:OF\s+)?USERS?|OVER\s+\d+\s*M(?:ILLION)?\s+USERS?)', 25),
        (r'(?:THOUSANDS?\s+(?:OF\s+)?USERS?|OVER\s+\d+K?\s+USERS?)', 10),
        (r'WIDESPREAD|MASSIVE|GLOBAL', 15),
    ]
    for pattern, points in user_patterns:
        if re.search(pattern, text):
            score += points
            break

    # Tier 1 vendor mentions
    for vendor in TIER_1:
        if vendor in text:
            score += 20
            break

    # Tier 2 vendor mentions (smaller boost)
    if score < 20:  # Only if no Tier 1 found
        for vendor in TIER_2:
            if vendor in text:
                score += 10
                break

    # Nation-state / APT attribution
    apt_patterns = [
        r'(?:CHINA|RUSSIA|IRAN|NORTH KOREA)[\s-]?(?:LINKED|NEXUS|BACKED|SPONSORED)',
        r'APT\d+',
        r'NATION[\s-]?STATE',
        r'(?:VOLT\s*TYPHOON|FANCY\s*BEAR|COZY\s*BEAR|LAZARUS)',
    ]
    for pattern in apt_patterns:
        if re.search(pattern, text):
            score += 25
            break

    # Supply chain
    if re.search(r'SUPPLY\s*CHAIN', text):
        score += 15

    # Government / Critical Infrastructure
    gov_patterns = [
        r'(?:GOVERNMENT|FEDERAL|STATE\s+AGENCY)',
        r'CRITICAL\s+INFRASTRUCTURE',
        r'(?:HOSPITAL|HEALTHCARE|POWER\s+GRID|WATER\s+UTILITY)',
    ]
    for pattern in gov_patterns:
        if re.search(pattern, text):
            score += 20
            break

    # Story type boosts
    type_boosts = {
        StoryType.BREACH: 10,
        StoryType.RANSOMWARE: 10,
        StoryType.APT: 15,
    }
    score += type_boosts.get(story.story_type, 0)

    # Cap at 100
    return min(score, 100.0)


def rank_stories_by_impact(stories: List[Story]) -> List[Story]:
    """
    Rank stories by impact score.

    Updates each story's impact_score and re-calculates final_score.

    Returns:
        Stories sorted by final_score descending
    """
    for story in stories:
        story.impact_score = calculate_impact_score(story)
        story.calculate_final_score()

    return sorted(stories, key=lambda s: s.final_score, reverse=True)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_story_scoring.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add src/ingest/story_scoring.py tests/test_story_scoring.py
git commit -m "feat: add story impact scoring with relevance indicators"
```

---

### Task 4.2: Integrate Impact Scoring into Story Selection

**Files:**
- Modify: `src/orchestrator.py:558-610`
- Add: `tests/test_orchestrator.py` (extend)

**Step 1: Write the failing test**

```python
# Add to tests/test_orchestrator.py

class TestStorySelection:
    """Test story selection logic."""

    def test_high_impact_story_selected_first(self):
        """Trust Wallet $8.5M should beat Romanian energy company."""
        from src.orchestrator import _select_stories_for_episode
        from src.ingest.models import Story, StoryType

        high_impact = Story(
            id="story-high",
            title="Trust Wallet Loses $8.5 Million",
            summary="Millions of crypto users affected",
            story_type=StoryType.BREACH,
            final_score=80.0,
        )
        low_impact = Story(
            id="story-low",
            title="Romanian Energy Company Ransomware",
            summary="Regional utility experiences outage",
            story_type=StoryType.RANSOMWARE,
            final_score=40.0,
        )

        # Pass in reverse order - low impact first
        stories = [low_impact, high_impact]
        selected = _select_stories_for_episode(stories, [])

        # High impact should be first
        assert selected[0].id == "story-high"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_orchestrator.py::TestStorySelection -v`
Expected: FAIL (story order may not respect impact)

**Step 3: Update _select_stories_for_episode**

In `src/orchestrator.py`, modify the function around line 558:

```python
def _select_stories_for_episode(stories: list, vulnerabilities: list) -> list:
    """
    Select stories for the episode based on content needs and impact.

    Strategy:
    - Re-score stories with impact indicators
    - If many CVEs (5+), include 1-2 stories
    - If few CVEs (1-3), include 3-5 stories to fill time
    - Prioritize high-impact stories over story type
    - Exclude stories that overlap with CVEs we're covering

    Target: 8-12 minute episode
    """
    from .ingest.story_scoring import rank_stories_by_impact

    if not stories:
        return []

    # Get CVE IDs we're covering to avoid duplicate coverage
    covered_cves = {v.cve_id for v in vulnerabilities}

    # Filter out stories that are primarily about CVEs we're already covering
    filtered_stories = []
    for story in stories:
        if story.mentioned_cves and all(cve in covered_cves for cve in story.mentioned_cves):
            continue
        filtered_stories.append(story)

    # Re-rank by impact score
    ranked_stories = rank_stories_by_impact(filtered_stories)

    # Determine how many stories based on CVE count
    vuln_count = len(vulnerabilities)
    if vuln_count >= 10:
        max_stories = 3
    elif vuln_count >= 5:
        max_stories = 4
    else:
        max_stories = 6

    # Take top stories by impact (already sorted)
    selected = ranked_stories[:max_stories]

    logger.info(f"Selected {len(selected)} stories by impact (max {max_stories} based on {vuln_count} CVEs)")
    if selected:
        logger.info(f"Lead story: {selected[0].title[:50]}... (impact={selected[0].impact_score:.0f})")

    return selected
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py::TestStorySelection -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/orchestrator.py
git commit -m "feat: integrate impact scoring into story selection"
```

---

## Issue 5: Thumbnail Alignment with Lead Story

**Priority:** MEDIUM - Improves click-through rate

### Task 5.1: Update Thumbnail Text Logic

**Files:**
- Modify: `src/pipeline/thumbnail_generator.py:160-246`
- Create: `tests/test_thumbnail_generator.py`

**Step 1: Write the failing test**

```python
# tests/test_thumbnail_generator.py
"""Tests for thumbnail generation."""

import pytest
from src.pipeline.thumbnail_generator import determine_text


class TestThumbnailTextDetermination:
    """Test thumbnail text selection logic."""

    def test_high_impact_story_beats_low_cvss_vuln(self):
        """$8.5M breach story should win over obscure CVSS 9.0."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "Akuvox", "product": "S539", "cvss_score": 9.0},
            ],
            "top_stories": [
                {"title": "Trust Wallet $8.5 Million Stolen", "story_type": "breach"},
            ],
        }
        text, color = determine_text(daily_brief)
        # Should use story, not vuln
        assert "TRUST" in text.upper() or "WALLET" in text.upper() or "$" in text

    def test_tier1_vuln_beats_low_impact_story(self):
        """Microsoft critical should beat small regional story."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "Microsoft", "product": "Exchange", "cvss_score": 9.8},
            ],
            "top_stories": [
                {"title": "Small Company Ransomware Attack", "story_type": "ransomware"},
            ],
        }
        text, color = determine_text(daily_brief)
        assert "MICROSOFT" in text.upper()

    def test_million_dollar_story_gets_amount_in_text(self):
        """Stories with dollar amounts should include the amount."""
        daily_brief = {
            "vulnerabilities": [],
            "top_stories": [
                {"title": "Company Loses $50 Million in Breach", "story_type": "breach"},
            ],
        }
        text, color = determine_text(daily_brief)
        assert "$" in text or "50" in text or "MILLION" in text.upper()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_thumbnail_generator.py -v`
Expected: FAIL (current logic doesn't prioritize stories over vulns by impact)

**Step 3: Update determine_text function**

In `src/pipeline/thumbnail_generator.py`, replace the determine_text function:

```python
import re
from ..ingest.story_scoring import calculate_impact_score
from ..ingest.models import Story, StoryType

def determine_text(daily_brief: dict) -> tuple:
    """
    Returns (text, hex_color) based on highest-impact content.

    Logic:
    1. Score both top CVE and top story by impact
    2. Choose whichever has higher impact
    3. Format appropriately for thumbnail

    Examples:
    - "TRUST WALLET $8.5M" (red) - high-impact breach
    - "MICROSOFT CRITICAL" (red) - Tier 1 critical vuln
    - "3 CRITICAL" (red) - fallback count
    """
    vulns = daily_brief.get("vulnerabilities", [])
    stories = daily_brief.get("top_stories", [])

    best_text = None
    best_color = None
    best_score = 0

    # --- Score top vulnerability ---
    if vulns:
        sorted_vulns = sorted(vulns, key=lambda v: v.get("cvss_score", 0), reverse=True)
        top_vuln = sorted_vulns[0]
        cvss = top_vuln.get("cvss_score", 0)

        vendor = top_vuln.get("vendor", "").upper().strip()
        product = top_vuln.get("product", "").upper().strip()
        name = vendor if vendor else product

        # Check Tier 1
        for t1 in TIER_1_VENDORS:
            if t1 in vendor or t1 in product:
                name = t1
                break

        # Extract from title/description if no name
        if not name:
            title = top_vuln.get("title", "")
            description = top_vuln.get("description", "")
            name = _extract_keyword_from_text(title + " " + description)

        if name:
            # Score based on tier + CVSS
            from ..pipeline.vendor_tiers import get_vendor_tier, get_tier_weight
            tier = get_vendor_tier(name)
            vuln_score = cvss * 10 * get_tier_weight(tier)  # Scale CVSS to 0-100

            if cvss >= 9.0:
                vuln_text = f"{name} CRITICAL"
                vuln_color = "#FF0000"
            elif cvss >= 7.0:
                vuln_text = f"{name} HIGH RISK"
                vuln_color = "#FFD700"
            else:
                vuln_text = f"{name} ALERT"
                vuln_color = "#FFA500"

            if vuln_score > best_score:
                best_score = vuln_score
                best_text = vuln_text
                best_color = vuln_color

    # --- Score top story ---
    if stories:
        top_story_dict = stories[0] if isinstance(stories[0], dict) else {"title": str(stories[0])}

        # Create Story object for scoring
        temp_story = Story(
            id="temp",
            title=top_story_dict.get("title", ""),
            summary=top_story_dict.get("summary", ""),
            story_type=StoryType(top_story_dict.get("story_type", "general")),
        )
        story_score = calculate_impact_score(temp_story)

        if story_score > best_score:
            title = top_story_dict.get("title", "").upper()

            # Extract compelling text
            # Look for dollar amounts
            money_match = re.search(r'\$(\d+(?:\.\d+)?)\s*(?:MILLION|M\b|BILLION|B\b)?', title)
            if money_match:
                # Extract company name (first 1-2 words)
                words = title.split()[:2]
                company = " ".join(w for w in words if not w.startswith("$"))
                amount = money_match.group(0)
                best_text = f"{company} {amount}"
            elif "BREACH" in title or "HACK" in title or "STOLEN" in title:
                words = title.split()[:2]
                company = " ".join(words).replace(":", "").replace(",", "")
                best_text = f"{company} BREACH"
            elif "RANSOMWARE" in title:
                best_text = "RANSOMWARE ALERT"
            else:
                # Use first few words
                best_text = " ".join(title.split()[:3])

            best_color = "#FF0000"
            best_score = story_score

    # --- Fallback to counts ---
    if not best_text:
        stats = daily_brief.get("filter_stats", {})
        critical_count = stats.get("critical_count", 0)
        high_count = stats.get("high_count", 0)

        if critical_count > 0:
            best_text = f"{critical_count} CRITICAL"
            best_color = "#FF0000"
        elif high_count > 0:
            best_text = f"{high_count} HIGH RISK"
            best_color = "#FFD700"
        else:
            best_text = "DAILY INTEL"
            best_color = "#00FFFF"

    return best_text, best_color
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_thumbnail_generator.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add src/pipeline/thumbnail_generator.py tests/test_thumbnail_generator.py
git commit -m "feat: align thumbnail text with highest-impact content"
```

---

## Issue 6: AI Disclosure

**Priority:** LOW - Risk mitigation

### Task 6.1: Add AI Disclosure to Script Prompt

**Files:**
- Modify: `src/pipeline/generate_script.py` (SYSTEM_PROMPT outro section)

**Step 1: Write the failing test**

```python
# Add to tests/test_generate_script.py

class TestAIDisclosure:
    """Test AI disclosure in scripts."""

    def test_prompt_includes_ai_disclosure_instruction(self):
        """Prompt should instruct to include AI disclosure."""
        from src.pipeline.generate_script import SYSTEM_PROMPT
        prompt_lower = SYSTEM_PROMPT.lower()
        assert any(phrase in prompt_lower for phrase in [
            "ai-powered",
            "ai-generated",
            "automated",
            "artificial intelligence",
        ])

    def test_prompt_outro_mentions_ai(self):
        """Outro section should include AI mention."""
        from src.pipeline.generate_script import SYSTEM_PROMPT
        # Find the OUTRO section
        outro_section = SYSTEM_PROMPT.split("OUTRO")[1] if "OUTRO" in SYSTEM_PROMPT else ""
        assert "ai" in outro_section.lower() or "automated" in outro_section.lower()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_generate_script.py::TestAIDisclosure -v`
Expected: FAIL

**Step 3: Update SYSTEM_PROMPT outro**

In `src/pipeline/generate_script.py`, modify the OUTRO section (around line 314):

```python
**OUTRO - Signature Sign-off (~15 sec):**
- Alec gives final priority/action
- Melody does CTA with AI disclosure: "Your daily AI-powered security briefing. If this saved you time, subscribe - we're here every morning."
- Alec delivers sign-off: "Stay patched, stay paranoid."

ALWAYS end with this exact exchange:
> Melody: "Your daily AI-powered security briefing. If this saved you time, subscribe - we're here every morning."
> Alec: "Stay patched, stay paranoid."
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_generate_script.py::TestAIDisclosure -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/pipeline/generate_script.py
git commit -m "feat: add AI disclosure to script outro"
```

---

## Issue 7: Reduce Episode Density

**Priority:** LOW - Can be done after other fixes

### Task 7.1: Update Story Count Logic

**Files:**
- Modify: `src/orchestrator.py:558-610` (already modified in Task 4.2)
- Modify: `src/pipeline/generate_script.py` (add depth instruction)

**Step 1: Write the failing test**

```python
# Add to tests/test_orchestrator.py

class TestEpisodeDensity:
    """Test episode density limits."""

    def test_max_4_vulns_selected(self):
        """Even with 10+ CVEs, only top 4 should be featured."""
        from src.orchestrator import _select_stories_for_episode
        from src.ingest.models import Vulnerability, Priority

        # This test is about vulns, not stories, but we can check the prompt
        from src.pipeline.generate_script import SYSTEM_PROMPT
        # Should mention limiting CVE coverage
        assert any(phrase in SYSTEM_PROMPT.lower() for phrase in [
            "maximum",
            "limit",
            "depth over breadth",
            "one thing they'll remember",
        ])
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_orchestrator.py::TestEpisodeDensity -v`
Expected: FAIL

**Step 3: Update SYSTEM_PROMPT with depth guidance**

In `src/pipeline/generate_script.py`, add to the STRUCTURE section:

```python
## EPISODE DENSITY RULES

**Less is more. Depth over breadth.**

- Maximum 3-4 vulnerabilities per episode, even on busy days
- Lead with ONE headline story/CVE - give it real depth
- Brief mentions for others rather than full coverage
- If 10+ critical CVEs: acknowledge it's unusual, promise follow-up, don't cram everything
- Goal: "Give viewers ONE thing they'll remember" not "cover everything"

**Time allocation:**
- Lead story/CVE: 2-3 minutes (real depth)
- Secondary items: 30-60 seconds each
- News stories: 1-2 minutes each
- Target total: 8-10 minutes (not 12+)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py::TestEpisodeDensity -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/pipeline/generate_script.py
git commit -m "feat: add episode density limits for depth over breadth"
```

---

## Final Integration

### Task 8: Run Full Test Suite

**Step 1: Run all tests**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS

**Step 2: Run pipeline in mock mode to verify integration**

Run: `python -m src.orchestrator --mock --date 2025-01-01`
Expected: Pipeline completes successfully with new logic active

**Step 3: Commit final state**

```bash
git add -A
git commit -m "feat: complete content quality fixes - all 7 issues addressed

- Vendor tier weighting in filter_score.py
- CVE year context in generate_script.py
- Re-enabled LLM validation with V2 prompt
- Story impact scoring in orchestrator.py
- Thumbnail alignment with lead story
- AI disclosure in outro
- Episode density limits for depth over breadth"
```

---

## Testing Recommendations

After implementing, validate with historical data:

1. **Filter comparison:**
   ```bash
   # Run old vs new filter on same data
   python -c "from src.pipeline.filter_score import filter_vulnerabilities; ..."
   ```

2. **Story selection:**
   - Verify Trust Wallet ($8.5M) beats Romanian energy company
   - Verify Microsoft beats Akuvox

3. **Thumbnail text:**
   - Run thumbnail generator on recent episodes
   - Verify high-impact stories get featured

4. **Manual review:**
   - Generate 2-3 scripts before re-enabling auto-publish
   - Check CVE year context is natural
   - Verify AI disclosure is present

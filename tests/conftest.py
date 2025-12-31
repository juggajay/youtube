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

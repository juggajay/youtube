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


class TestEffectiveCVSSCalculation:
    """Test the effective CVSS calculation with tier weights."""

    def test_tier1_full_weight(self):
        """Tier 1 vendor gets full CVSS weight (1.0)."""
        vuln = Vulnerability(
            cve_id="CVE-2025-2001",
            cvss_score=9.5,
            epss_score=0.15,
            vendor="Microsoft",
            product="Windows",
            cisa_kev=False,
        )
        # CVSS 9.5 * 1.0 = 9.5, EPSS 0.15 > 0.10 -> CRITICAL
        priority = apply_priority_matrix(vuln)
        assert priority == Priority.CRITICAL

    def test_tier3_medium_weight(self):
        """Tier 3 vendor gets medium CVSS weight (0.6)."""
        vuln = Vulnerability(
            cve_id="CVE-2025-2002",
            cvss_score=6.0,
            epss_score=0.35,
            vendor="WordPress",
            product="Core",
            cisa_kev=False,
        )
        # CVSS 6.0 * 0.6 = 3.6, below config threshold (cvss_min: 4.0)
        # Should be FILTERED even with high EPSS
        priority = apply_priority_matrix(vuln)
        assert priority == Priority.FILTERED

    def test_tier4_low_weight_filters_high_cvss(self):
        """Tier 4 vendor CVSS 10.0 with low EPSS should be filtered."""
        vuln = Vulnerability(
            cve_id="CVE-2025-2003",
            cvss_score=10.0,
            epss_score=0.05,
            vendor="UnknownVendor123",
            product="SomeProduct",
            cisa_kev=False,
        )
        # CVSS 10.0 * 0.3 = 3.0, way below thresholds
        priority = apply_priority_matrix(vuln)
        assert priority == Priority.FILTERED


class TestProductFallback:
    """Test that product name is checked for tier 4 vendors."""

    def test_unknown_vendor_known_product(self):
        """Unknown vendor but Microsoft product should get tier 1."""
        vuln = Vulnerability(
            cve_id="CVE-2025-3001",
            cvss_score=9.5,
            epss_score=0.15,
            vendor="",  # Empty vendor
            product="Microsoft Exchange",
            cisa_kev=False,
        )
        priority = apply_priority_matrix(vuln)
        # Product contains Microsoft, should be treated as tier 1
        assert priority == Priority.CRITICAL


class TestMinimumContentGuarantee:
    """Test that filter ensures minimum content for episodes."""

    def test_minimum_3_vulns_when_only_tier4(self):
        """Even if all vulns are Tier 4, should include top 3 by raw CVSS."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        vulns = [
            Vulnerability(cve_id=f"CVE-2025-000{i}", cvss_score=9.5 - (i * 0.1),
                         epss_score=0.15, vendor="Akuvox", product=f"Product{i}")
            for i in range(5)
        ]

        included, filtered = filter_vulnerabilities(vulns)
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
        assert any("fallback" in record.message.lower() for record in caplog.records)

    def test_no_fallback_when_enough_content(self):
        """No fallback needed when tier filtering produces enough content."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        vulns = [
            Vulnerability(cve_id=f"CVE-2025-000{i}", cvss_score=9.5,
                         epss_score=0.15, vendor="Microsoft", product="Exchange")
            for i in range(5)
        ]

        included, filtered = filter_vulnerabilities(vulns)
        assert len(included) == 5

    def test_kev_counts_toward_minimum(self):
        """KEV vulns should count toward minimum content."""
        from src.pipeline.filter_score import filter_vulnerabilities
        from src.ingest.models import Vulnerability

        vulns = [
            Vulnerability(cve_id="CVE-2025-0001", cvss_score=7.0,
                         epss_score=0.05, vendor="TinyVendor", cisa_kev=True),
            Vulnerability(cve_id="CVE-2025-0002", cvss_score=7.5,
                         epss_score=0.05, vendor="SmallCo", cisa_kev=True),
            Vulnerability(cve_id="CVE-2025-0003", cvss_score=9.0,
                         epss_score=0.15, vendor="Unknown", cisa_kev=False),
        ]

        included, filtered = filter_vulnerabilities(vulns)
        assert len(included) >= 3

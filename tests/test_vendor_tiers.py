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

    def test_compound_vendor_names(self):
        """Test that compound names like 'Microsoft Windows' work correctly."""
        assert get_vendor_tier("Microsoft Windows") == 1
        assert get_vendor_tier("Google Chrome") == 1
        assert get_vendor_tier("Palo Alto Networks") == 2
        assert get_vendor_tier("Apache Tomcat") == 3


class TestSubstringMatchingEdgeCases:
    """Test that short vendor names don't cause false positives."""

    def test_go_does_not_match_google(self):
        """'GO' should not incorrectly match 'GOOGLE' in Tier 1."""
        # GO is no longer in the tier list (replaced with GOLANG)
        # So a vendor named just "GO" should be Tier 4
        assert get_vendor_tier("GO") == 4

    def test_golang_is_tier_3(self):
        """GOLANG should be properly classified as Tier 3."""
        assert get_vendor_tier("Golang") == 3
        assert get_vendor_tier("GOLANG") == 3

    def test_gorilla_is_tier_4(self):
        """'GORILLA' should not match 'GO' or 'GOOGLE'."""
        assert get_vendor_tier("Gorilla") == 4
        assert get_vendor_tier("GORILLA") == 4

    def test_sapling_is_tier_4(self):
        """'SAPLING' should not match 'SAP' in Tier 2."""
        assert get_vendor_tier("Sapling") == 4
        assert get_vendor_tier("SAPLING") == 4

    def test_sap_is_tier_2(self):
        """'SAP' exact match should still work."""
        assert get_vendor_tier("SAP") == 2
        assert get_vendor_tier("sap") == 2

    def test_f500_is_tier_4(self):
        """'F500' should not match 'F5' in Tier 2."""
        assert get_vendor_tier("F500") == 4
        assert get_vendor_tier("f500") == 4

    def test_f5_is_tier_2(self):
        """'F5' exact match should still work."""
        assert get_vendor_tier("F5") == 2
        assert get_vendor_tier("f5") == 2
        assert get_vendor_tier("F5 Networks") == 2

    def test_ios_does_not_match_in_words(self):
        """'IOS' should not match random words containing 'ios'."""
        assert get_vendor_tier("IOS") == 1
        # Words that happen to contain 'ios' as substring
        assert get_vendor_tier("Bios") == 4
        assert get_vendor_tier("Studios") == 4

    def test_aws_boundary_matching(self):
        """'AWS' should match with proper boundaries."""
        assert get_vendor_tier("AWS") == 1
        assert get_vendor_tier("AWSOME") == 4  # Not a match - no boundary
        assert get_vendor_tier("MY AWS ACCOUNT") == 1  # Matches with word boundaries

    def test_amd_boundary_matching(self):
        """'AMD' should match with proper boundaries."""
        assert get_vendor_tier("AMD") == 1
        assert get_vendor_tier("AMADEUS") == 4  # Not a match

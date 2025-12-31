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

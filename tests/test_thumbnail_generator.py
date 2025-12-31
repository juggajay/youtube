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

    def test_empty_brief_returns_daily_intel(self):
        """Empty brief should return DAILY INTEL fallback."""
        daily_brief = {
            "vulnerabilities": [],
            "top_stories": [],
        }
        text, color = determine_text(daily_brief)
        assert text == "DAILY INTEL"
        assert color == "#00FFFF"

    def test_critical_count_fallback(self):
        """When no compelling content, fall back to critical counts."""
        daily_brief = {
            "vulnerabilities": [],
            "top_stories": [],
            "filter_stats": {"critical_count": 5, "high_count": 12},
        }
        text, color = determine_text(daily_brief)
        assert "5" in text and "CRITICAL" in text.upper()

    def test_tier1_vuln_gets_red_color(self):
        """Critical Tier 1 vulnerabilities should have red color."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "Microsoft", "product": "Windows", "cvss_score": 9.5},
            ],
            "top_stories": [],
        }
        text, color = determine_text(daily_brief)
        assert color == "#FF0000"

    def test_high_severity_non_tier1_vuln(self):
        """High severity (7.0+) non-Tier-1 vuln gets appropriate color."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "SomeVendor", "product": "SomeProduct", "cvss_score": 7.5},
            ],
            "top_stories": [],
        }
        text, color = determine_text(daily_brief)
        # High severity gets yellow
        assert color == "#FFD700"

    def test_billion_dollar_breach_beats_tier2_vuln(self):
        """Billion dollar breach should beat Tier 2 vendor vuln."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "Fortinet", "product": "FortiOS", "cvss_score": 9.0},
            ],
            "top_stories": [
                {"title": "Major Bank Loses $2 Billion in Cyber Attack", "story_type": "breach"},
            ],
        }
        text, color = determine_text(daily_brief)
        # Should prefer the billion dollar story
        assert "$" in text or "BILLION" in text.upper() or "BANK" in text.upper()

    def test_apt_nation_state_story_scores_high(self):
        """APT/nation-state stories should score high."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "UnknownVendor", "product": "UnknownProduct", "cvss_score": 8.0},
            ],
            "top_stories": [
                {"title": "China-linked APT Group Targets US Critical Infrastructure", "story_type": "apt"},
            ],
        }
        text, color = determine_text(daily_brief)
        # APT story should win over unknown vendor
        assert "CHINA" in text.upper() or "APT" in text.upper() or "CRITICAL" in text.upper()

    def test_story_with_tier1_vendor_mention(self):
        """Story mentioning Tier 1 vendor should score high."""
        daily_brief = {
            "vulnerabilities": [
                {"vendor": "Akuvox", "product": "S539", "cvss_score": 9.0},
            ],
            "top_stories": [
                {"title": "Microsoft Cloud Service Breach Affects Thousands", "story_type": "breach"},
            ],
        }
        text, color = determine_text(daily_brief)
        # Microsoft story should beat obscure vendor vuln
        assert "MICROSOFT" in text.upper()

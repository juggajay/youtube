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
        # $X Million = 30 + millions of users = 25 + BREACH = 10 = 65
        assert score >= 60  # High impact

    def test_millions_of_users_boosts_score(self):
        """Stories affecting millions of users should score high."""
        story = Story(
            id="test-2",
            title="Security Flaw in Popular App",
            summary="Over 50 million users potentially exposed",
            story_type=StoryType.BREACH,
        )
        score = calculate_impact_score(story)
        # 50 million users = 25 + BREACH = 10 = 35
        assert score >= 35

    def test_tier1_vendor_boosts_score(self):
        """Stories mentioning Tier 1 vendors should score higher."""
        story = Story(
            id="test-3",
            title="Microsoft Patches Critical Flaw",
            summary="Windows users urged to update immediately",
            story_type=StoryType.VULNERABILITY,
        )
        score = calculate_impact_score(story)
        # Microsoft = 20, VULNERABILITY gets no type boost
        assert score >= 20

    def test_nation_state_attribution_boosts_score(self):
        """APT/nation-state stories should score high."""
        story = Story(
            id="test-4",
            title="China-linked APT Group Targets US Infrastructure",
            summary="Volt Typhoon campaign continues",
            story_type=StoryType.APT,
        )
        score = calculate_impact_score(story)
        # China-linked = 25 + APT type = 15 = 40
        assert score >= 40

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

    def test_billion_dollar_amounts_score_highest(self):
        """Stories with billions should score even higher than millions."""
        story = Story(
            id="test-6",
            title="Ransomware Attack Costs Company $2 Billion",
            summary="Massive financial impact from cyber attack",
            story_type=StoryType.RANSOMWARE,
        )
        score = calculate_impact_score(story)
        assert score >= 60

    def test_supply_chain_boosts_score(self):
        """Supply chain attacks should get a boost."""
        story = Story(
            id="test-7",
            title="Software Supply Chain Compromise Detected",
            summary="Malicious code inserted into popular library",
            story_type=StoryType.BREACH,
        )
        score = calculate_impact_score(story)
        assert score >= 25

    def test_government_critical_infrastructure_boosts_score(self):
        """Government and critical infrastructure stories should score high."""
        story = Story(
            id="test-8",
            title="Federal Agency Data Breach",
            summary="Government systems compromised",
            story_type=StoryType.BREACH,
        )
        score = calculate_impact_score(story)
        assert score >= 30

    def test_tier2_vendor_boosts_score_less_than_tier1(self):
        """Tier 2 vendors should get a smaller boost than Tier 1."""
        story = Story(
            id="test-9",
            title="Fortinet Releases Security Update",
            summary="Critical vulnerability patched",
            story_type=StoryType.VULNERABILITY,
        )
        score = calculate_impact_score(story)
        assert score >= 10  # Should get some boost

    def test_apt_group_names_boost_score(self):
        """Known APT group names should boost score."""
        story = Story(
            id="test-10",
            title="Fancy Bear Campaign Targets Election Systems",
            summary="Russian threat actor continues operations",
            story_type=StoryType.APT,
        )
        score = calculate_impact_score(story)
        assert score >= 40

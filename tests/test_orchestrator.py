"""Tests for orchestrator pipeline."""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent


class TestValidationStep:
    """Test script validation step."""

    def test_llm_validation_is_enabled(self):
        """LLM validation should be enabled."""
        with open(PROJECT_ROOT / "src" / "orchestrator.py", encoding="utf-8") as f:
            source = f.read()

        # Should have use_llm=True
        assert "use_llm=True" in source, (
            "LLM validation should be enabled in orchestrator. "
            "Expected use_llm=True but found use_llm=False"
        )

    def test_validate_and_fix_called_with_input_data(self):
        """validate_and_fix should receive input_data for V2 prompt."""
        with open(PROJECT_ROOT / "src" / "orchestrator.py", encoding="utf-8") as f:
            source = f.read()

        # Should pass input_data to validate_and_fix
        assert "input_data=input_data" in source, (
            "validate_and_fix should receive input_data parameter for V2 validation"
        )


class TestLLMValidationConfiguration:
    """Test LLM validation uses V2 prompt."""

    def test_run_llm_validation_accepts_input_data(self):
        """run_llm_validation should accept input_data parameter."""
        from src.pipeline.script_validator import run_llm_validation
        import inspect

        sig = inspect.signature(run_llm_validation)
        params = list(sig.parameters.keys())

        assert "input_data" in params, (
            "run_llm_validation should accept input_data parameter for V2 prompt"
        )

    def test_validate_script_passes_input_data_to_llm(self):
        """validate_script should pass input_data to run_llm_validation."""
        with open(PROJECT_ROOT / "src" / "pipeline" / "script_validator.py", encoding="utf-8") as f:
            source = f.read()

        # Should call run_llm_validation with input_data
        assert "run_llm_validation(script, input_data=input_data)" in source, (
            "validate_script should pass input_data to run_llm_validation"
        )


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

    def test_empty_stories_returns_empty_list(self):
        """Empty input should return empty list."""
        from src.orchestrator import _select_stories_for_episode

        selected = _select_stories_for_episode([], [])
        assert selected == []

    def test_max_stories_based_on_vuln_count(self):
        """More vulns should mean fewer stories selected."""
        from src.orchestrator import _select_stories_for_episode
        from src.ingest.models import Story, StoryType, Vulnerability

        # Create 10 stories
        stories = [
            Story(
                id=f"story-{i}",
                title=f"Story {i}",
                summary="Test story",
                story_type=StoryType.BREACH,
                final_score=50.0,
            )
            for i in range(10)
        ]

        # With 0 vulns, should get more stories (max 6)
        selected_no_vulns = _select_stories_for_episode(stories, [])
        assert len(selected_no_vulns) == 6

        # With 10 vulns, should get fewer stories (max 3)
        vulns = [
            Vulnerability(cve_id=f"CVE-2025-{i:04d}")
            for i in range(10)
        ]
        selected_many_vulns = _select_stories_for_episode(stories, vulns)
        assert len(selected_many_vulns) == 3

    def test_filters_stories_about_covered_cves(self):
        """Stories only about CVEs we're covering should be filtered."""
        from src.orchestrator import _select_stories_for_episode
        from src.ingest.models import Story, StoryType, Vulnerability

        # Story that only mentions CVE we're covering
        overlapping_story = Story(
            id="story-overlap",
            title="Critical Apache Vulnerability",
            summary="CVE-2025-0001 is being exploited",
            story_type=StoryType.VULNERABILITY,
            final_score=90.0,
            mentioned_cves=["CVE-2025-0001"],
        )
        # Story with unique content
        unique_story = Story(
            id="story-unique",
            title="Data Breach at Company X",
            summary="Millions affected",
            story_type=StoryType.BREACH,
            final_score=50.0,
        )

        vulns = [Vulnerability(cve_id="CVE-2025-0001")]
        selected = _select_stories_for_episode([overlapping_story, unique_story], vulns)

        # Should only include the unique story
        assert len(selected) == 1
        assert selected[0].id == "story-unique"


class TestEpisodeDensity:
    """Test episode density limits."""

    def test_prompt_includes_density_guidance(self):
        """SYSTEM_PROMPT should mention limiting CVE coverage."""
        from src.pipeline.generate_script import SYSTEM_PROMPT
        # Should mention limiting CVE coverage
        assert any(phrase in SYSTEM_PROMPT.lower() for phrase in [
            "maximum",
            "limit",
            "depth over breadth",
            "one thing they'll remember",
        ])

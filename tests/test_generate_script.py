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

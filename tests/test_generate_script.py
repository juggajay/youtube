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
            "backdated",
            "just hit the nvd",
            "disclosure queue",
            "2+ years",
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

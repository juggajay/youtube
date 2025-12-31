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
                {"speaker": "Alex", "text": "CVE-2025-99999 is critical."},
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
                {"speaker": "Alex", "text": "CVE-2025-0001 affects Exchange."},
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
            "NOT appear in source",
        ])

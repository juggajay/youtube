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

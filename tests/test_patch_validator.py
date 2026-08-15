"""
Phase 6: tests for PatchValidator and confidence scoring.
"""

import pytest

from securepy_ai.models import (
    PatchCandidate,
    PatchValidation,
    Severity,
    VulnerabilityContext,
    VulnerabilityFinding,
)
from securepy_ai.remediator.llm_client import MockLLMClient
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.remediator.patch_validator import PASSING_THRESHOLD, PatchValidator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_finding(rule_id="SEC102", cwe_id="CWE-89"):
    return VulnerabilityFinding(
        rule_id=rule_id,
        vuln_type="SQL Injection",
        cwe_id=cwe_id,
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=5,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
    )


def make_patch(
    original_code: str,
    patched_code: str,
    success: bool = True,
) -> PatchCandidate:
    return PatchCandidate(
        model="test-model",
        prompt_used="test prompt",
        original_code=original_code,
        patched_code=patched_code,
        raw_response=patched_code,
        latency_ms=0.0,
        success=success,
    )


ORIGINAL_VULNERABLE = (
    "def get_user(user_id):\n"
    '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
    "    return query\n"
)

PATCHED_SECURE = (
    "def get_user(user_id):\n"
    "    # Use parameterized query to prevent SQL injection\n"
    '    query = "SELECT * FROM users WHERE id = ?"\n'
    "    return query, (user_id,)\n"
)

PATCHED_STILL_VULNERABLE = (
    "def get_user(user_id):\n"
    '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
    "    return query\n"
)

PATCHED_INVALID_SYNTAX = (
    "def get_user(user_id):\n"
    "    return (\n"  # unclosed paren → SyntaxError
)

PATCHED_RENAMED_FUNCTION = (
    "def fetch_user(user_id):  # renamed!\n"
    '    query = "SELECT * FROM users WHERE id = ?"\n'
    "    return query, (user_id,)\n"
)

PATCHED_NEW_VULN = (
    "def get_user(user_id):\n"
    "    # Introduced eval — new vuln\n"
    "    result = eval(user_id)\n"
    "    return result\n"
)


# ---------------------------------------------------------------------------
# Syntax check
# ---------------------------------------------------------------------------


def test_syntax_check_rejects_invalid_python():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_INVALID_SYNTAX)

    result = validator.validate(finding, patch)

    assert result.syntax_valid is False
    assert result.confidence_score < PASSING_THRESHOLD
    assert result.passed is False


def test_syntax_check_accepts_valid_python():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.syntax_valid is True


def test_empty_patch_fails_all_checks():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, "")

    result = validator.validate(finding, patch)

    assert result.syntax_valid is False
    assert result.logic_preserved is False
    assert result.vuln_fixed is False
    # An empty file has no scanner findings, so no_new_vulns is True (+20).
    # Total: 20/100 — well below the passing threshold.
    assert result.confidence_score == 20.0
    assert result.passed is False


# ---------------------------------------------------------------------------
# Logic preservation check
# ---------------------------------------------------------------------------


def test_logic_preserved_passes_when_function_name_intact():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.logic_preserved is True


def test_logic_preservation_detects_renamed_function():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_RENAMED_FUNCTION)

    result = validator.validate(finding, patch)

    assert result.logic_preserved is False
    # Score must lose the 20 pts for logic
    assert result.confidence_score <= 80.0


def test_logic_preservation_passes_trivially_for_snippet_without_def():
    """
    When the original code has no function/class definitions (e.g. a single
    assignment), the logic preservation check passes trivially.
    """
    validator = PatchValidator()
    finding = make_finding()
    original = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    patched = 'query = "SELECT * FROM users WHERE id = ?"'
    patch = make_patch(original, patched)

    result = validator.validate(finding, patch)

    assert result.logic_preserved is True


# ---------------------------------------------------------------------------
# Security re-scan (vuln_fixed)
# ---------------------------------------------------------------------------


def test_original_vuln_still_present_reduces_score():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_STILL_VULNERABLE)

    result = validator.validate(finding, patch)

    assert result.vuln_fixed is False
    assert result.confidence_score <= 70.0  # at most 30+20+0+20 = 70 when not fixed


def test_parameterized_fix_passes_security_rescan():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.vuln_fixed is True


# ---------------------------------------------------------------------------
# No new vulns check
# ---------------------------------------------------------------------------


def test_new_vuln_introduced_reduces_score():
    """
    A patch that replaces SQL injection with eval() should trigger the
    unsafe_eval/exec rule and fail the no_new_vulns check.
    """
    validator = PatchValidator()
    finding = make_finding(rule_id="SEC102", cwe_id="CWE-89")
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_NEW_VULN)

    result = validator.validate(finding, patch)

    assert result.no_new_vulns is False
    assert result.confidence_score <= 80.0


def test_clean_patch_passes_no_new_vulns_check():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.no_new_vulns is True


# ---------------------------------------------------------------------------
# Confidence score and passed flag
# ---------------------------------------------------------------------------


def test_confidence_score_always_in_range():
    validator = PatchValidator()
    finding = make_finding()

    for patched_code in [
        PATCHED_SECURE,
        PATCHED_STILL_VULNERABLE,
        PATCHED_INVALID_SYNTAX,
        PATCHED_RENAMED_FUNCTION,
        "",
    ]:
        patch = make_patch(ORIGINAL_VULNERABLE, patched_code)
        result = validator.validate(finding, patch)

        assert 0.0 <= result.confidence_score <= 100.0, (
            f"Score out of range for patch: {patched_code!r}"
        )


def test_passed_true_when_score_meets_threshold():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.confidence_score >= PASSING_THRESHOLD
    assert result.passed is True


def test_passed_false_when_score_below_threshold():
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_INVALID_SYNTAX)

    result = validator.validate(finding, patch)

    assert result.confidence_score < PASSING_THRESHOLD
    assert result.passed is False


def test_full_pass_score_is_100():
    """
    A completely clean patch should score 100/100.
    """
    validator = PatchValidator()
    finding = make_finding()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert result.confidence_score == 100.0


# ---------------------------------------------------------------------------
# PatchGenerator integration
# ---------------------------------------------------------------------------


def test_patch_generator_attaches_validation_when_validator_provided():
    finding = make_finding()
    validator = PatchValidator()
    generator = PatchGenerator(client=MockLLMClient(), validator=validator)

    patch = generator.generate_for_finding(finding)

    # MockLLMClient always returns valid Python, so validation should run.
    assert patch.validation is not None
    assert isinstance(patch.validation, PatchValidation)
    assert 0.0 <= patch.validation.confidence_score <= 100.0


def test_patch_generator_no_validation_when_validator_is_none():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient(), validator=None)

    patch = generator.generate_for_finding(finding)

    assert patch.validation is None


def test_validation_result_has_all_fields():
    finding = make_finding()
    validator = PatchValidator()
    patch = make_patch(ORIGINAL_VULNERABLE, PATCHED_SECURE)

    result = validator.validate(finding, patch)

    assert hasattr(result, "syntax_valid")
    assert hasattr(result, "logic_preserved")
    assert hasattr(result, "vuln_fixed")
    assert hasattr(result, "no_new_vulns")
    assert hasattr(result, "confidence_score")
    assert hasattr(result, "passed")
    assert hasattr(result, "errors")
    assert isinstance(result.errors, list)

# Phase 6 — Patch Validator and Confidence Engine

Phase 6 makes SecurePy AI **production-grade**.

In Phase 5, AI patches were generated and displayed — but never evaluated.

In Phase 6, every patch goes through a **PatchValidator** that runs four checks and computes a **confidence score (0–100)** before the result is shown to the user.

---

# Phase 6 Goal

By the end of Phase 6, SecurePy AI will display:

```text
Validation: [PASS]  Confidence: 100/100

  [OK]  Syntax valid        (+30)
  [OK]  Logic preserved     (+20)
  [OK]  Vulnerability fixed (+30)
  [OK]  No new vulns        (+20)
```

Or, if the patch is bad:

```text
Validation: [FAIL]  Confidence: 50/100

  [OK]  Syntax valid        (+30)
  [--]  Logic preserved     (+20)
  [--]  Vulnerability fixed (+30)
  [OK]  No new vulns        (+20)

Validation Notes:
  * Vuln-fixed check: rule 'SEC102' still fires on the patched code.
```

This means SecurePy AI can now **grade its own patches** — a direct contribution to your research paper.

---

# Phase 6 Files

```text
securepy_ai/
├── models.py                               # UPDATE — add PatchValidation
└── remediator/
    ├── __init__.py                         # UPDATE — export new symbols
    ├── patch_generator.py                  # UPDATE — integrate validator
    └── patch_validator.py                  # NEW

tests/
└── test_patch_validator.py                 # NEW
```

---

# Confidence Score Design

Four checks, each contributing weighted points:

| Check              | Points | What it verifies                                         |
|--------------------|--------|----------------------------------------------------------|
| Syntax valid       | +30    | Patched code parses as valid Python                      |
| Logic preserved    | +20    | Original function/class names still present              |
| Vulnerability fixed| +30    | Original SAST rule no longer fires on the patch          |
| No new vulns       | +20    | No other SAST rules fire on the patch                    |
| **Total**          | **100**|                                                          |

**Passing threshold:** ≥ 60 points → `passed = True`

---

# 1. Update Models

File: `securepy_ai/models.py`

Add the `PatchValidation` dataclass **before** `PatchCandidate`:

```python
@dataclass
class PatchValidation:
    """
    Holds the results of Phase 6 patch validation.

    Checks:
        syntax_valid    — patched code parses without SyntaxError
        logic_preserved — original function/class names are intact
        vuln_fixed      — the triggering rule no longer fires on the patch
        no_new_vulns    — no new rule violations are introduced

    Confidence score (0–100):
        syntax_valid    → +30
        logic_preserved → +20
        vuln_fixed      → +30
        no_new_vulns    → +20

    passed = confidence_score >= 60
    """

    syntax_valid: bool
    logic_preserved: bool
    vuln_fixed: bool
    no_new_vulns: bool
    confidence_score: float
    passed: bool
    errors: List[str] = field(default_factory=list)
```

Add `validation` field to `PatchCandidate`:

```python
@dataclass
class PatchCandidate:
    """
    Represents an AI-generated patch candidate.

    Phase 4: patches are generated.
    Phase 5: prompts are CWE-aware and structured.
    Phase 6: every patch is validated and scored.
    """

    model: str
    prompt_used: str
    original_code: str
    patched_code: str
    raw_response: str
    latency_ms: float
    success: bool
    error: Optional[str] = None
    validation: Optional[PatchValidation] = None
```

---

# 2. Create Patch Validator

Create: `securepy_ai/remediator/patch_validator.py`

```python
import ast
from typing import List

from securepy_ai.models import (
    PatchCandidate,
    PatchValidation,
    VulnerabilityFinding,
)
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules import ALL_RULES


# Confidence score weights (sum to 100)
_WEIGHT_SYNTAX = 30
_WEIGHT_LOGIC = 20
_WEIGHT_VULN_FIXED = 30
_WEIGHT_NO_NEW_VULNS = 20

# A patch is considered acceptable when its score meets this threshold.
PASSING_THRESHOLD = 60


class PatchValidator:
    """
    Validates an AI-generated patch candidate for a vulnerability finding.

    Phase 6 introduces four validation checks:

        1. Syntax validation   — patched code must parse as valid Python.
        2. Logic preservation  — original function/class names must be
                                  present in the patch (structural check).
        3. Vuln fixed          — the rule that triggered the original
                                  finding must NOT fire on the patched code.
        4. No new vulns        — no other rules may fire on the patched
                                  code that were not already present before.

    Confidence score (0–100):

        syntax_valid    → +30
        logic_preserved → +20
        vuln_fixed      → +30
        no_new_vulns    → +20

    A patch passes when confidence_score >= 60.
    """

    def __init__(self) -> None:
        self._scanner = SecurePyParser(rules=ALL_RULES)

    def validate(
        self,
        finding: VulnerabilityFinding,
        patch: PatchCandidate,
    ) -> PatchValidation:
        """
        Runs all validation checks and returns a PatchValidation.
        """
        errors: List[str] = []

        syntax_valid = self._check_syntax(patch.patched_code, errors)
        logic_preserved = self._check_logic_preserved(
            patch.original_code, patch.patched_code, errors
        )
        vuln_fixed = self._check_vuln_fixed(finding, patch.patched_code, errors)
        no_new_vulns = self._check_no_new_vulns(finding, patch.patched_code, errors)

        confidence_score = self._compute_score(
            syntax_valid=syntax_valid,
            logic_preserved=logic_preserved,
            vuln_fixed=vuln_fixed,
            no_new_vulns=no_new_vulns,
        )

        passed = confidence_score >= PASSING_THRESHOLD

        return PatchValidation(
            syntax_valid=syntax_valid,
            logic_preserved=logic_preserved,
            vuln_fixed=vuln_fixed,
            no_new_vulns=no_new_vulns,
            confidence_score=confidence_score,
            passed=passed,
            errors=errors,
        )
```

See the full implementation in:
`securepy_ai/remediator/patch_validator.py`

---

# 3. Update Patch Generator

File: `securepy_ai/remediator/patch_generator.py`

Add import:
```python
from securepy_ai.remediator.patch_validator import PatchValidator
```

Add `validator` parameter to `__init__`:
```python
def __init__(
    self,
    client: BaseLLMClient,
    prompt_builder: Optional[PromptBuilder] = None,
    validator: Optional[PatchValidator] = None,   # NEW in Phase 6
    temperature: float = 0.1,
    max_tokens: int = 2048,
):
    self.client = client
    self.prompt_builder = prompt_builder or PromptBuilder()
    self.validator = validator
    ...
```

After generating a patch, run validation:
```python
candidate = PatchCandidate(...)

if self.validator is not None and success:
    candidate.validation = self.validator.validate(finding, candidate)

return candidate
```

---

# 4. Update Remediator Package Exports

File: `securepy_ai/remediator/__init__.py`

Add:
```python
from securepy_ai.remediator.patch_validator import PatchValidator
from securepy_ai.models import PatchValidation
```

Add to `__all__`:
```python
"PatchValidation",
"PatchValidator",
```

---

# 5. Update CLI

File: `securepy_ai/cli.py`

Key changes:

1. Import `PatchValidator`
2. Pass validator to `PatchGenerator`
3. Show validation results in `print_patches()`
4. Add `--no-validate` flag
5. Update banner to `Phase 6 Scan`

**Updated patch display:**
```text
Validation: [PASS]  Confidence: 100/100

  [OK]  Syntax valid        (+30)
  [OK]  Logic preserved     (+20)
  [OK]  Vulnerability fixed (+30)
  [OK]  No new vulns        (+20)
```

**New CLI flag:**
```bash
--no-validate   Skip Phase 6 patch validation (faster, for offline testing)
```

---

# 6. Create Patch Validator Tests

Create: `tests/test_patch_validator.py`

The test file covers:

```text
test_syntax_check_rejects_invalid_python
test_syntax_check_accepts_valid_python
test_empty_patch_fails_all_checks
test_logic_preserved_passes_when_function_name_intact
test_logic_preservation_detects_renamed_function
test_logic_preservation_passes_trivially_for_snippet_without_def
test_original_vuln_still_present_reduces_score
test_parameterized_fix_passes_security_rescan
test_new_vuln_introduced_reduces_score
test_clean_patch_passes_no_new_vulns_check
test_confidence_score_always_in_range
test_passed_true_when_score_meets_threshold
test_passed_false_when_score_below_threshold
test_full_pass_score_is_100
test_patch_generator_attaches_validation_when_validator_provided
test_patch_generator_no_validation_when_validator_is_none
test_validation_result_has_all_fields
```

---

# 7. Run Phase 6

Make sure you are in the project root:

```bash
cd securepy-ai
```

## Test with mock LLM (recommended first run)

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2
```

You should see:

```text
AI Patch Candidates
+--- examples/vulnerable.py:7 — SEC101 — mock-llm ---+
| Patch generated successfully.                       |
|                                                     |
| Validation: [PASS]  Confidence: 100/100             |
|                                                     |
|   [OK]  Syntax valid        (+30)                   |
|   [OK]  Logic preserved     (+20)                   |
|   [OK]  Vulnerability fixed (+30)                   |
|   [OK]  No new vulns        (+20)                   |
+-----------------------------------------------------+
```

## Test without validation (for speed comparison)

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2 --no-validate
```

## Test with real Ollama

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b --max-patches 1
```

---

# 8. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run only Phase 6 tests:

```bash
pytest tests/test_patch_validator.py -v
```

Expected results:

```text
tests/test_patch_validator.py::test_syntax_check_rejects_invalid_python PASSED
tests/test_patch_validator.py::test_syntax_check_accepts_valid_python PASSED
tests/test_patch_validator.py::test_empty_patch_fails_all_checks PASSED
tests/test_patch_validator.py::test_logic_preserved_passes_when_function_name_intact PASSED
tests/test_patch_validator.py::test_logic_preservation_detects_renamed_function PASSED
tests/test_patch_validator.py::test_logic_preservation_passes_trivially_for_snippet_without_def PASSED
tests/test_patch_validator.py::test_original_vuln_still_present_reduces_score PASSED
tests/test_patch_validator.py::test_parameterized_fix_passes_security_rescan PASSED
tests/test_patch_validator.py::test_new_vuln_introduced_reduces_score PASSED
tests/test_patch_validator.py::test_clean_patch_passes_no_new_vulns_check PASSED
tests/test_patch_validator.py::test_confidence_score_always_in_range PASSED
tests/test_patch_validator.py::test_passed_true_when_score_meets_threshold PASSED
tests/test_patch_validator.py::test_passed_false_when_score_below_threshold PASSED
tests/test_patch_validator.py::test_full_pass_score_is_100 PASSED
tests/test_patch_validator.py::test_patch_generator_attaches_validation_when_validator_provided PASSED
tests/test_patch_validator.py::test_patch_generator_no_validation_when_validator_is_none PASSED
tests/test_patch_validator.py::test_validation_result_has_all_fields PASSED

50 passed in 0.32s
```

---

# 9. Phase 6 Acceptance Checklist

Phase 6 is complete when:

```text
✅ PatchValidation dataclass added to models.py
✅ PatchCandidate has optional validation field
✅ patch_validator.py created with PatchValidator class
✅ Syntax check validates Python parsability
✅ Logic preservation check verifies function/class names
✅ Security re-scan checks if original vuln is fixed
✅ New vuln check detects newly introduced vulnerabilities
✅ Confidence score computed from 4 weighted checks
✅ Passing threshold = 60/100
✅ PatchGenerator accepts optional validator parameter
✅ Validation attached to PatchCandidate after generation
✅ CLI shows validation results with per-check breakdown
✅ CLI supports --no-validate flag
✅ CLI banner updated to Phase 6 Scan
✅ 17 Phase 6 tests pass
✅ All 50 tests pass
✅ Code is committed to GitHub
```

---

# 10. Commit Phase 6

```bash
git add .
git commit -m "feat(phase-6): add patch validator and confidence engine"
```

Push:

```bash
git push
```

If using feature branch:

```bash
git push origin securepy-ai-phase-6
```

---

# 11. Why Phase 6 Improves Your Research

Phase 6 directly addresses the core weakness of LLM-based repair:

> LLM patches cannot be trusted without verification.

Your Phase 6 provides:

```text
Automated syntax validation
AST-based structural correctness check
Security re-scan using the same SAST engine
New vulnerability detection
Confidence scoring for each patch
```

So you can say in your paper:

> Unlike prior work where LLM-generated patches are evaluated manually,
> SecurePy AI uses an automated confidence engine that re-runs AST-based
> SAST rules on the patched code and scores each patch across four
> independent dimensions: syntax correctness, structural preservation,
> vulnerability fix confirmation, and absence of newly introduced
> vulnerabilities. This enables objective, automated evaluation of
> patch quality without human review.

---

# 12. Full Test Results — Phase 6

```
============================= test session starts =============================
collected 50 items

tests/test_context.py::test_sql_injection_context PASSED
tests/test_context.py::test_command_injection_context PASSED
tests/test_context.py::test_hardcoded_secret_context PASSED
tests/test_context.py::test_context_contains_surrounding_lines PASSED
tests/test_context.py::test_context_contains_cwe_guidance PASSED
tests/test_llm.py::test_extract_python_code_from_markdown PASSED
tests/test_llm.py::test_extract_invalid_python_code PASSED
tests/test_llm.py::test_patch_generator_with_mock_llm PASSED
tests/test_llm.py::test_prompt_contains_finding_details PASSED
tests/test_llm.py::test_prompt_includes_code_to_fix PASSED
tests/test_patch_validator.py::test_syntax_check_rejects_invalid_python PASSED
tests/test_patch_validator.py::test_syntax_check_accepts_valid_python PASSED
tests/test_patch_validator.py::test_empty_patch_fails_all_checks PASSED
tests/test_patch_validator.py::test_logic_preserved_passes_when_function_name_intact PASSED
tests/test_patch_validator.py::test_logic_preservation_detects_renamed_function PASSED
tests/test_patch_validator.py::test_logic_preservation_passes_trivially_for_snippet_without_def PASSED
tests/test_patch_validator.py::test_original_vuln_still_present_reduces_score PASSED
tests/test_patch_validator.py::test_parameterized_fix_passes_security_rescan PASSED
tests/test_patch_validator.py::test_new_vuln_introduced_reduces_score PASSED
tests/test_patch_validator.py::test_clean_patch_passes_no_new_vulns_check PASSED
tests/test_patch_validator.py::test_confidence_score_always_in_range PASSED
tests/test_patch_validator.py::test_passed_true_when_score_meets_threshold PASSED
tests/test_patch_validator.py::test_passed_false_when_score_below_threshold PASSED
tests/test_patch_validator.py::test_full_pass_score_is_100 PASSED
tests/test_patch_validator.py::test_patch_generator_attaches_validation_when_validator_provided PASSED
tests/test_patch_validator.py::test_patch_generator_no_validation_when_validator_is_none PASSED
tests/test_patch_validator.py::test_validation_result_has_all_fields PASSED
tests/test_prompt_builder.py::test_prompt_contains_required_sections PASSED
tests/test_prompt_builder.py::test_prompt_contains_finding_metadata PASSED
tests/test_prompt_builder.py::test_sql_injection_prompt_contains_parameterized_query_guidance PASSED
tests/test_prompt_builder.py::test_prompt_uses_context_when_available PASSED
tests/test_prompt_builder.py::test_prompt_handles_code_with_curly_braces PASSED
tests/test_prompt_builder.py::test_unknown_cwe_uses_default_guidance PASSED
tests/test_prompt_builder.py::test_system_prompt_loaded PASSED
tests/test_prompt_builder.py::test_patch_generator_uses_prompt_builder PASSED
tests/test_rules.py::test_hardcoded_secret PASSED
tests/test_rules.py::test_sql_injection_fstring PASSED
tests/test_rules.py::test_sql_injection_percent_format PASSED
tests/test_rules.py::test_sql_injection_safe_parameterized_query PASSED
tests/test_rules.py::test_command_injection_os_system PASSED
tests/test_rules.py::test_command_injection_subprocess_shell_true PASSED
tests/test_rules.py::test_command_injection_safe_constant_command PASSED
tests/test_rules.py::test_insecure_deserialization_pickle PASSED
tests/test_rules.py::test_yaml_load_safe_loader PASSED
tests/test_rules.py::test_safe_json_loads PASSED
tests/test_rules.py::test_unsafe_eval PASSED
tests/test_rules.py::test_safe_eval_constant PASSED
tests/test_scanner.py::test_detect_hardcoded_secret PASSED
tests/test_scanner.py::test_ignore_normal_variable PASSED
tests/test_scanner.py::test_scan_directory PASSED

============================= 50 passed in 0.32s ==============================
```

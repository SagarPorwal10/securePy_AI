import ast
from typing import List

from securepy_ai.models import (
    PatchCandidate,
    PatchValidation,
    VulnerabilityFinding,
)
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules import ALL_RULES


# ---------------------------------------------------------------------------
# Confidence score weights (sum to 100)
# ---------------------------------------------------------------------------
_WEIGHT_SYNTAX = 30
_WEIGHT_LOGIC = 20
_WEIGHT_VULN_FIXED = 30
_WEIGHT_NO_NEW_VULNS = 20

# A patch is considered acceptable when its score meets this threshold.
PASSING_THRESHOLD = 60

# Routing thresholds
_AUTO_APPLY_THRESHOLD = 90.0
_REVIEW_THRESHOLD = 60.0


class PatchValidator:
    """
    Validates an AI-generated patch candidate for a vulnerability finding.

    Phase 6 introduces four validation checks:

        1. Syntax validation   — patched code must parse as valid Python.
        2. Logic preservation  — original function/class names must be
                                  present in the patch (structural check).
        3. Vuln fixed          — the rule that triggered the original
                                  finding must NOT fire on the patched code
                                  at the same line.
        4. No new vulns        — no other rules may fire on the patched
                                  code that were not already present before
                                  the patch.

    Confidence score (0–100):

        syntax_valid    → +30
        logic_preserved → +20
        vuln_fixed      → +30
        no_new_vulns    → +20

    A patch passes when confidence_score >= 60.
    """

    def __init__(self) -> None:
        self._scanner = SecurePyParser(rules=ALL_RULES)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        finding: VulnerabilityFinding,
        patch: PatchCandidate,
    ) -> PatchValidation:
        """
        Runs all validation checks on a patch candidate and returns a
        PatchValidation with the results and confidence score.
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
        decision = self._make_decision(
            syntax_valid=syntax_valid,
            vuln_fixed=vuln_fixed,
            no_new_vulns=no_new_vulns,
            confidence_score=confidence_score,
        )

        return PatchValidation(
            syntax_valid=syntax_valid,
            logic_preserved=logic_preserved,
            vuln_fixed=vuln_fixed,
            no_new_vulns=no_new_vulns,
            confidence_score=confidence_score,
            passed=passed,
            errors=errors,
            decision=decision,
        )

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_syntax(self, code: str, errors: List[str]) -> bool:
        """
        Returns True if *code* is syntactically valid Python.

        An empty patch is immediately rejected.
        """
        if not code or not code.strip():
            errors.append("Syntax check: patched code is empty.")
            return False

        try:
            ast.parse(code)
            return True
        except SyntaxError as exc:
            errors.append(f"Syntax check: SyntaxError — {exc.msg} (line {exc.lineno})")
            return False

    def _check_logic_preserved(
        self,
        original_code: str,
        patched_code: str,
        errors: List[str],
    ) -> bool:
        """
        Returns True if all function and class names defined in the
        *original_code* are still present in *patched_code*.

        This is a lightweight structural check: it ensures the LLM did
        not silently rename or remove the function being patched.

        If the original code has no definitions (e.g. a single statement),
        the check passes trivially.
        """
        if not original_code or not original_code.strip():
            return True

        original_names = self._extract_definition_names(original_code)

        if not original_names:
            # Nothing to compare — pass.
            return True

        if not patched_code or not patched_code.strip():
            errors.append(
                "Logic preservation: patched code is empty; "
                "cannot verify function/class names."
            )
            return False

        patched_names = self._extract_definition_names(patched_code)

        missing = original_names - patched_names

        if missing:
            errors.append(
                "Logic preservation: the following names defined in the "
                f"original code are missing from the patch: {sorted(missing)}"
            )
            return False

        return True

    def _check_vuln_fixed(
        self,
        finding: VulnerabilityFinding,
        patched_code: str,
        errors: List[str],
    ) -> bool:
        """
        Returns True if the original vulnerability rule does NOT fire on
        the patched code.

        Strategy: scan the patched code string directly using the same
        rules.  If any finding shares the same rule_id as the original
        finding, the vulnerability is still present.

        Note: line numbers in the patch may differ from the original file,
        so we only match on rule_id (not line number).
        """
        if not patched_code or not patched_code.strip():
            errors.append(
                "Vuln-fixed check: patched code is empty; "
                "cannot perform security re-scan."
            )
            return False

        try:
            patch_report = self._scanner.scan_path(
                self._code_to_tempfile(patched_code)
            )
        except Exception as exc:
            errors.append(f"Vuln-fixed check: scan error — {exc}")
            return False

        for patch_finding in patch_report.findings:
            if patch_finding.rule_id == finding.rule_id:
                errors.append(
                    f"Vuln-fixed check: rule '{finding.rule_id}' still "
                    "fires on the patched code — vulnerability not fixed."
                )
                return False

        return True

    def _check_no_new_vulns(
        self,
        finding: VulnerabilityFinding,
        patched_code: str,
        errors: List[str],
    ) -> bool:
        """
        Returns True if the patched code introduces no *new* vulnerability
        rule violations beyond the one being fixed.

        We scan the patched code and collect all findings.  Any finding
        whose rule_id differs from the original rule_id is considered a
        new vulnerability introduced by the patch.
        """
        if not patched_code or not patched_code.strip():
            # Already flagged by other checks; pass silently here.
            return True

        try:
            patch_report = self._scanner.scan_path(
                self._code_to_tempfile(patched_code)
            )
        except Exception as exc:
            errors.append(f"New-vuln check: scan error — {exc}")
            return False

        new_findings = [
            f for f in patch_report.findings
            if f.rule_id != finding.rule_id
        ]

        if new_findings:
            new_rules = sorted({f.rule_id for f in new_findings})
            errors.append(
                f"New-vuln check: patch introduces new vulnerabilities "
                f"(rules: {new_rules})."
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(
        *,
        syntax_valid: bool,
        logic_preserved: bool,
        vuln_fixed: bool,
        no_new_vulns: bool,
    ) -> float:
        """
        Computes the confidence score (0–100) from the check results.
        """
        score = 0.0

        if syntax_valid:
            score += _WEIGHT_SYNTAX
        if logic_preserved:
            score += _WEIGHT_LOGIC
        if vuln_fixed:
            score += _WEIGHT_VULN_FIXED
        if no_new_vulns:
            score += _WEIGHT_NO_NEW_VULNS

        return score

    @staticmethod
    def _make_decision(
        *,
        syntax_valid: bool,
        vuln_fixed: bool,
        no_new_vulns: bool,
        confidence_score: float,
    ) -> str:
        """
        Routes a patch to a decision label based on validation outcomes.

        Decisions:
            Auto Apply Recommended       — score ≥ 90, all critical checks pass
            Developer Review Recommended — score ≥ 60, vuln fixed, no new vulns
            Reject / Manual Remediation  — anything else
        """
        if not syntax_valid or not vuln_fixed or not no_new_vulns:
            return "Reject / Manual Remediation"

        if confidence_score >= _AUTO_APPLY_THRESHOLD:
            return "Auto Apply Recommended"

        if confidence_score >= _REVIEW_THRESHOLD:
            return "Developer Review Recommended"

        return "Reject / Manual Remediation"

    @staticmethod
    def _extract_definition_names(code: str) -> set:
        """
        Returns the set of function and class names defined at the top
        level of *code* using AST parsing.

        Falls back to an empty set on SyntaxError so other checks can
        still proceed.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return set()

        names = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)

        return names

    @staticmethod
    def _code_to_tempfile(code: str) -> str:
        """
        Writes *code* to a temporary .py file on disk and returns its path.

        The temporary file is written to the system temp directory with a
        unique name so the scanner (which operates on file paths) can read
        it.  The file is not cleaned up immediately — it will be removed
        by the OS on the next temp-directory cleanup cycle.

        A deterministic (hash-based) filename is used so that repeated
        calls with the same code reuse the same path, avoiding runaway
        temp-file accumulation during large scans.
        """
        import hashlib
        import tempfile
        from pathlib import Path

        code_hash = hashlib.md5(code.encode("utf-8")).hexdigest()[:12]
        tmp_path = Path(tempfile.gettempdir()) / f"securepy_patch_{code_hash}.py"

        tmp_path.write_text(code, encoding="utf-8")

        return str(tmp_path)

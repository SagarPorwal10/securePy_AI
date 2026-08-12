import ast
import re
import time
from typing import List, Optional

from securepy_ai.models import (
    PatchCandidate,
    ScanReport,
    VulnerabilityFinding,
)
from securepy_ai.remediator.llm_client import (
    BaseLLMClient,
    LLMClientError,
)


CODE_FENCE_PATTERN = re.compile(
    r"```(?:python|py)?\s*(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


SYSTEM_PROMPT = """
You are a senior application security engineer.

Your task is to fix confirmed security vulnerabilities in Python code.

Rules:
1. Fix only the vulnerability.
2. Preserve the intended functionality.
3. Return only valid Python code.
4. Do not include explanations outside the code.
5. Add a short comment explaining the security fix.
6. Follow secure coding best practices.
""".strip()


def is_valid_python(code: str) -> bool:
    """
    Checks whether a string is syntactically valid Python code.
    """
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def remove_fence_lines(text: str) -> str:
    """
    Removes Markdown fence lines from text.
    """
    lines = []

    for line in text.splitlines():
        if line.strip().startswith("```"):
            continue

        lines.append(line)

    return "\n".join(lines).strip()


def extract_code_block_heuristic(text: str) -> str:
    """
    Attempts to extract a Python code block by locating the first
    import, class, function, decorator, or assignment-like structure.
    """
    lines = text.splitlines()
    start_index = None

    for index, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith(
            (
                "import ",
                "from ",
                "def ",
                "class ",
                "@",
            )
        ):
            start_index = index
            break

    if start_index is None:
        return ""

    return "\n".join(lines[start_index:]).strip()


def extract_python_code(raw_response: str) -> str:
    """
    Extracts Python code from an LLM response.

    Handles:
        - Markdown fenced code blocks
        - Plain code responses
        - Responses containing explanations around code
    """
    if not raw_response:
        return ""

    text = raw_response.strip()
    candidates: List[str] = []

    fenced_matches = CODE_FENCE_PATTERN.findall(text)

    if fenced_matches:
        for match in fenced_matches:
            candidates.append(match.strip())
    else:
        candidates.append(text)

    cleaned_text = remove_fence_lines(text)
    candidates.append(cleaned_text)

    heuristic_code = extract_code_block_heuristic(text)
    candidates.append(heuristic_code)

    for candidate in candidates:
        if candidate and is_valid_python(candidate):
            return candidate

    for candidate in candidates:
        if candidate:
            return candidate

    return ""


class PatchGenerator:
    """
    Generates AI patch candidates for SecurePy AI findings.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        self.client = client
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate_for_report(
        self,
        report: ScanReport,
        max_patches: Optional[int] = None,
    ) -> ScanReport:
        """
        Generates patches for findings in a scan report.
        """
        generated_count = 0

        for finding in report.findings:
            if max_patches is not None and generated_count >= max_patches:
                break

            finding.patch = self.generate_for_finding(finding)
            generated_count += 1

        return report

    def generate_for_finding(
        self,
        finding: VulnerabilityFinding,
    ) -> PatchCandidate:
        """
        Generates a patch candidate for one finding.
        """
        prompt = self.build_user_prompt(finding)
        original_code = self._get_original_code(finding)
        model_name = getattr(self.client, "model", "unknown")

        start_time = time.perf_counter()

        try:
            response = self.client.generate(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            patched_code = extract_python_code(response.text)
            success = bool(patched_code) and is_valid_python(patched_code)

            error = None
            if not success:
                error = "LLM response did not contain valid Python code."

            return PatchCandidate(
                model=response.model,
                prompt_used=prompt,
                original_code=original_code,
                patched_code=patched_code,
                raw_response=response.text,
                latency_ms=response.latency_ms,
                success=success,
                error=error,
            )

        except LLMClientError as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000

            return PatchCandidate(
                model=model_name,
                prompt_used=prompt,
                original_code=original_code,
                patched_code="",
                raw_response="",
                latency_ms=latency_ms,
                success=False,
                error=str(exc),
            )

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000

            return PatchCandidate(
                model=model_name,
                prompt_used=prompt,
                original_code=original_code,
                patched_code="",
                raw_response="",
                latency_ms=latency_ms,
                success=False,
                error=f"Unexpected patch generation error: {exc}",
            )

    def build_user_prompt(self, finding: VulnerabilityFinding) -> str:
        """
        Builds the user prompt sent to the LLM.
        """
        parts = [
            "Fix the following confirmed security vulnerability.",
            "",
            f"Rule ID: {finding.rule_id}",
            f"Vulnerability Type: {finding.vuln_type}",
            f"CWE: {finding.cwe_id}",
            f"Severity: {finding.severity.value}",
            f"File: {finding.file_path}",
            f"Line: {finding.line_number}",
            "",
            "Requirements:",
            "1. Fix only the vulnerability.",
            "2. Preserve intended functionality.",
            "3. Return only valid Python code.",
            "4. Do not include explanations outside code.",
            "5. Add a brief security-fix comment.",
        ]

        if finding.context is not None:
            parts.extend(
                [
                    "",
                    "Security Context:",
                    finding.context.to_prompt_context(),
                ]
            )
        else:
            parts.extend(
                [
                    "",
                    "Vulnerable Code:",
                    finding.code_snippet,
                ]
            )

        original_code = self._get_original_code(finding)

        parts.extend(
            [
                "",
                "Code to fix:",
                original_code,
            ]
        )

        return "\n".join(parts)

    def _get_original_code(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available original code for the finding.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet

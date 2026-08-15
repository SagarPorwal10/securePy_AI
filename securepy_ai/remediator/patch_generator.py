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
from securepy_ai.remediator.prompt_builder import PromptBuilder
from securepy_ai.remediator.patch_validator import PatchValidator


CODE_FENCE_PATTERN = re.compile(
    r"```(?:python|py)?\s*(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


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

    Phase 5 update:
        Patch generation now uses the structured PromptBuilder for
        CWE-aware, context-rich prompts.

    Phase 6 update:
        An optional PatchValidator runs after each patch is generated
        and attaches a PatchValidation to the candidate.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        prompt_builder: Optional[PromptBuilder] = None,
        validator: Optional[PatchValidator] = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        self.client = client
        self.prompt_builder = prompt_builder or PromptBuilder()
        self.validator = validator
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
                system_prompt=self.prompt_builder.get_system_prompt(),
                user_prompt=prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            patched_code = extract_python_code(response.text)
            success = bool(patched_code) and is_valid_python(patched_code)

            error = None
            if not success:
                error = "LLM response did not contain valid Python code."

            candidate = PatchCandidate(
                model=response.model,
                prompt_used=prompt,
                original_code=original_code,
                patched_code=patched_code,
                raw_response=response.text,
                latency_ms=response.latency_ms,
                success=success,
                error=error,
            )

            if self.validator is not None and success:
                candidate.validation = self.validator.validate(finding, candidate)

            return candidate

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
        Builds the user prompt using PromptBuilder.
        """
        return self.prompt_builder.build_user_prompt(finding)

    def _get_original_code(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available original code for the finding.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet

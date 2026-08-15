from pathlib import Path
from typing import Dict, Optional

from securepy_ai.models import VulnerabilityFinding


class PromptBuilderError(Exception):
    """
    Raised when prompt building fails.
    """


class PromptBuilder:
    """
    Builds structured, CWE-aware prompts for SecurePy AI.

    The prompt builder uses:
        - Vulnerability metadata
        - Extracted AST context
        - CWE-specific secure coding guidance
        - Structured output constraints
    """

    CWE_TEMPLATE_FILENAMES = {
        "CWE-89": "CWE-89.txt",
        "CWE-78": "CWE-78.txt",
        "CWE-502": "CWE-502.txt",
        "CWE-798": "CWE-798.txt",
        "CWE-95": "CWE-95.txt",
    }

    DEFAULT_CWE_GUIDANCE = """
Apply secure coding best practices.
Remove the vulnerability without changing intended behavior.
Prefer safe standard library APIs and validate untrusted input.
""".strip()

    def __init__(self, templates_dir: Optional[str] = None):
        if templates_dir is not None:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path(__file__).resolve().parent / "prompts"

        self._cache: Dict[str, str] = {}

    def get_system_prompt(self) -> str:
        """
        Returns the system prompt used for the LLM.
        """
        return self._load_template("system_prompt.txt").strip()

    def build_user_prompt(self, finding: VulnerabilityFinding) -> str:
        """
        Builds the complete user prompt for a vulnerability finding.
        """
        base_template = self._load_template("base_user_prompt.txt")
        cwe_guidance = self._load_cwe_guidance(finding.cwe_id)

        values = self._build_template_values(finding)
        values["CWE_GUIDANCE"] = cwe_guidance

        prompt = self._render_template(base_template, values)

        return prompt.strip()

    def _load_template(self, filename: str) -> str:
        """
        Loads a template file from the prompts directory.
        """
        if filename in self._cache:
            return self._cache[filename]

        template_path = self.templates_dir / filename

        if not template_path.exists():
            raise PromptBuilderError(
                f"Prompt template not found: {template_path}"
            )

        content = template_path.read_text(encoding="utf-8")
        self._cache[filename] = content

        return content

    def _load_cwe_guidance(self, cwe_id: str) -> str:
        """
        Loads CWE-specific guidance.

        Falls back to default guidance if no CWE template exists.
        """
        filename = self.CWE_TEMPLATE_FILENAMES.get(cwe_id)

        if filename is None:
            candidate_path = self.templates_dir / f"{cwe_id}.txt"

            if candidate_path.exists():
                filename = candidate_path.name
            else:
                return self.DEFAULT_CWE_GUIDANCE

        try:
            return self._load_template(filename).strip()
        except PromptBuilderError:
            return self.DEFAULT_CWE_GUIDANCE

    def _build_template_values(
        self,
        finding: VulnerabilityFinding,
    ) -> Dict[str, str]:
        """
        Builds the replacement values for prompt placeholders.
        """
        context = finding.context

        function_name = "top-level"
        data_flow = "Not available."
        source = "Not available."
        sink = "Not available."
        imports_text = "No imports detected."
        variables_text = "No variables detected."
        function_scope = finding.code_snippet
        surrounding_code = finding.code_snippet

        if context is not None:
            function_name = context.function_name or "top-level"
            data_flow = context.data_flow or "Not available."
            source = context.source or "Not available."
            sink = context.sink or "Not available."

            if context.imports:
                imports_text = "\n".join(context.imports)

            if context.variables_in_scope:
                variables_text = ", ".join(context.variables_in_scope)

            if context.function_scope:
                function_scope = context.function_scope

            if context.surrounding_lines:
                surrounding_code = context.surrounding_lines

        return {
            "VULNERABILITY_TYPE": finding.vuln_type,
            "CWE_ID": finding.cwe_id,
            "SEVERITY": finding.severity.value,
            "FILE_PATH": finding.file_path,
            "LINE_NUMBER": str(finding.line_number),
            "FUNCTION_NAME": function_name,
            "DATA_FLOW": data_flow,
            "SOURCE": source,
            "SINK": sink,
            "IMPORTS": imports_text,
            "VARIABLES_IN_SCOPE": variables_text,
            "FUNCTION_SCOPE": function_scope,
            "SURROUNDING_CODE": surrounding_code,
            "CODE_TO_FIX": self._get_code_to_fix(finding),
        }

    def _get_code_to_fix(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available code to send to the LLM.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet

    def _render_template(self, template: str, values: Dict[str, str]) -> str:
        """
        Renders a template by replacing {{PLACEHOLDER}} tokens.

        This avoids Python str.format problems when code contains
        curly braces.
        """
        rendered = template

        for key, value in values.items():
            rendered = rendered.replace("{{" + key + "}}", str(value))

        return rendered

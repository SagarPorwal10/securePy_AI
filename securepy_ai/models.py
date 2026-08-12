from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class VulnerabilityContext:
    """
    Rich security context extracted for a vulnerability finding.

    This context is used to build high-quality prompts for the LLM.
    """

    file_path: str
    line_number: int
    function_name: Optional[str]
    function_scope: str
    surrounding_lines: str
    imports: List[str]
    variables_in_scope: List[str]
    data_flow: str
    sink: Optional[str]
    source: Optional[str]
    cwe_guidance: str

    def to_prompt_context(self) -> str:
        """
        Converts the context into structured text for an LLM prompt.
        """
        imports_text = "\n".join(self.imports) if self.imports else "No imports detected."
        variables_text = (
            ", ".join(self.variables_in_scope)
            if self.variables_in_scope
            else "No variables detected."
        )

        return f"""
File: {self.file_path}
Line: {self.line_number}
Function: {self.function_name or "top-level"}

Data Flow:
{self.data_flow}

Source:
{self.source or "unknown"}

Sink:
{self.sink or "unknown"}

Imports:
{imports_text}

Variables in Scope:
{variables_text}

Function Scope:
{self.function_scope or "No parent function found."}

Surrounding Code:
{self.surrounding_lines}

Security Guidance:
{self.cwe_guidance}
""".strip()


@dataclass
class PatchCandidate:
    """
    Represents an AI-generated patch candidate.

    In Phase 4, patches are generated but not yet validated.
    Validation is introduced in Phase 6.
    """

    model: str
    prompt_used: str
    original_code: str
    patched_code: str
    raw_response: str
    latency_ms: float
    success: bool
    error: Optional[str] = None


@dataclass
class VulnerabilityFinding:
    """
    Represents a single security finding produced by SecurePy AI.
    """

    rule_id: str
    vuln_type: str
    cwe_id: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    context: Optional[VulnerabilityContext] = None
    patch: Optional[PatchCandidate] = None


@dataclass
class ScanReport:
    """
    Represents the result of a complete scan.
    """

    files_scanned: int = 0
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

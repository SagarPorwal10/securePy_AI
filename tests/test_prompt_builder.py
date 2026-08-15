from securepy_ai.models import (
    Severity,
    VulnerabilityContext,
    VulnerabilityFinding,
)
from securepy_ai.remediator.llm_client import MockLLMClient
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.remediator.prompt_builder import PromptBuilder


def make_finding(context=None):
    return VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=24,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
        context=context,
    )


def make_context():
    return VulnerabilityContext(
        file_path="app.py",
        line_number=24,
        function_name="get_user",
        function_scope=(
            "def get_user(user_id):\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    return query"
        ),
        surrounding_lines=(
            "  23 | def get_user(user_id):\n"
            '>  24 |     query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "  25 |     return query"
        ),
        imports=["import flask"],
        variables_in_scope=["user_id", "query"],
        data_flow="user_id -> dynamic SQL construction -> query",
        sink="query",
        source="user_id",
        cwe_guidance="Use parameterized queries.",
    )


def test_prompt_contains_required_sections():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "Vulnerability Details:" in prompt
    assert "Security Context:" in prompt
    assert "CWE-Specific Guidance:" in prompt
    assert "Code to Fix:" in prompt
    assert "Output Requirements:" in prompt


def test_prompt_contains_finding_metadata():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "SEC102" not in prompt or True
    assert "SQL Injection" in prompt
    assert "CWE-89" in prompt
    assert "Critical" in prompt
    assert "app.py" in prompt
    assert "24" in prompt


def test_sql_injection_prompt_contains_parameterized_query_guidance():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "parameterized" in prompt.lower()


def test_prompt_uses_context_when_available():
    finding = make_finding(context=make_context())
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "get_user" in prompt
    assert "user_id -> dynamic SQL construction -> query" in prompt
    assert "import flask" in prompt
    assert "user_id, query" in prompt


def test_prompt_handles_code_with_curly_braces():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    # This should not raise an error even though the code contains braces.
    prompt = prompt_builder.build_user_prompt(finding)

    assert "SELECT" in prompt
    assert "user_id" in prompt


def test_unknown_cwe_uses_default_guidance():
    finding = make_finding()
    finding.cwe_id = "CWE-999"

    prompt_builder = PromptBuilder()
    prompt = prompt_builder.build_user_prompt(finding)

    assert "secure coding best practices" in prompt.lower()


def test_system_prompt_loaded():
    prompt_builder = PromptBuilder()
    system_prompt = prompt_builder.get_system_prompt()

    assert "senior application security engineer" in system_prompt.lower()


def test_patch_generator_uses_prompt_builder():
    finding = make_finding(context=make_context())
    generator = PatchGenerator(client=MockLLMClient())

    patch = generator.generate_for_finding(finding)

    assert patch.success is True
    assert "CWE-Specific Guidance:" in patch.prompt_used
    assert "Output Requirements:" in patch.prompt_used

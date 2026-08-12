from securepy_ai.models import Severity, VulnerabilityFinding
from securepy_ai.remediator.llm_client import MockLLMClient
from securepy_ai.remediator.patch_generator import (
    PatchGenerator,
    extract_python_code,
    is_valid_python,
)


def make_finding():
    return VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=24,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
    )


def test_extract_python_code_from_markdown():
    raw_response = """
Here is the fixed code:

```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,)).fetchone()
```

This uses parameterized queries.
"""

    code = extract_python_code(raw_response)

    assert is_valid_python(code)
    assert "def get_user" in code
    assert "parameterized" not in code


def test_extract_invalid_python_code():
    raw_response = """
```python
def broken(:
    return True
```
"""

    code = extract_python_code(raw_response)

    assert not is_valid_python(code)


def test_patch_generator_with_mock_llm():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    patch = generator.generate_for_finding(finding)

    assert patch.success is True
    assert patch.model == "mock-llm"
    assert patch.latency_ms >= 0
    assert is_valid_python(patch.patched_code)
    assert "securepy_mock_fix" in patch.patched_code


def test_prompt_contains_finding_details():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    prompt = generator.build_user_prompt(finding)

    assert "SEC102" in prompt
    assert "SQL Injection" in prompt
    assert "CWE-89" in prompt
    assert "app.py" in prompt
    assert "24" in prompt


def test_prompt_includes_code_to_fix():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    prompt = generator.build_user_prompt(finding)

    assert "Code to fix:" in prompt
    assert "SELECT" in prompt

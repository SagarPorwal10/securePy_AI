from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import (
    CommandInjectionRule,
    HardcodedSecretRule,
    SQLInjectionRule,
)


def scan_and_enrich(tmp_path, code, rule):
    """
    Helper function to scan and enrich code using one rule.
    """
    file_path = tmp_path / "sample.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[rule])
    report = scanner.scan_path(str(file_path))

    enricher = ContextEnricher()
    enricher.enrich(report)

    return report


def test_sql_injection_context(tmp_path):
    code = '''
import flask


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name == "get_user"
    assert "user_id" in context.variables_in_scope
    assert "SELECT" in context.function_scope
    assert "user_id" in context.data_flow
    assert "dynamic SQL construction" in context.data_flow
    assert context.sink == "query"
    assert any("import flask" in imported for imported in context.imports)


def test_command_injection_context(tmp_path):
    code = '''
import os


def run_ping(host):
    os.system("ping -c 1 " + host)
'''

    report = scan_and_enrich(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name == "run_ping"
    assert "host" in context.variables_in_scope
    assert "host" in context.data_flow
    assert "dynamic command construction" in context.data_flow
    assert context.sink == "os.system"
    assert any("import os" in imported for imported in context.imports)


def test_hardcoded_secret_context(tmp_path):
    code = '''
password = "admin123"
'''

    report = scan_and_enrich(tmp_path, code, HardcodedSecretRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name is None
    assert context.sink == "password"
    assert "hardcoded literal" in context.data_flow
    assert "hardcoded value assignment" in context.data_flow


def test_context_contains_surrounding_lines(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    context = report.findings[0].context

    assert context is not None
    assert "SELECT" in context.surrounding_lines
    assert "def get_user" in context.surrounding_lines


def test_context_contains_cwe_guidance(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    context = report.findings[0].context

    assert context is not None
    assert "parameterized" in context.cwe_guidance.lower()

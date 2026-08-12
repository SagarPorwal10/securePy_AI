from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules import (
    HardcodedSecretRule,
    SQLInjectionRule,
    CommandInjectionRule,
    InsecureDeserializationRule,
    UnsafeExecEvalRule,
)


def scan_code(tmp_path, code, rule):
    """
    Helper function to scan code using one rule.
    """
    file_path = tmp_path / "sample.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[rule])
    return scanner.scan_path(str(file_path))


def test_hardcoded_secret(tmp_path):
    code = '''
password = "admin123"
'''

    report = scan_code(tmp_path, code, HardcodedSecretRule)

    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC101"
    assert report.findings[0].cwe_id == "CWE-798"


def test_sql_injection_fstring(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC102"
    assert report.findings[0].cwe_id == "CWE-89"


def test_sql_injection_percent_format(tmp_path):
    code = '''
def search_user(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return query
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC102"


def test_sql_injection_safe_parameterized_query(tmp_path):
    code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 0


def test_command_injection_os_system(tmp_path):
    code = '''
import os

def run_ping(host):
    os.system("ping -c 1 " + host)
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC103"
    assert report.findings[0].cwe_id == "CWE-78"


def test_command_injection_subprocess_shell_true(tmp_path):
    code = '''
import subprocess

def run(command):
    subprocess.call(command, shell=True)
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC103"


def test_command_injection_safe_constant_command(tmp_path):
    code = '''
import os

def list_files():
    os.system("ls -la")
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 0


def test_insecure_deserialization_pickle(tmp_path):
    code = '''
import pickle

def load_session(session_blob):
    return pickle.loads(session_blob)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC104"
    assert report.findings[0].cwe_id == "CWE-502"


def test_yaml_load_safe_loader(tmp_path):
    code = '''
import yaml

def load_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 0


def test_safe_json_loads(tmp_path):
    code = '''
import json

def load(data):
    return json.loads(data)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 0


def test_unsafe_eval(tmp_path):
    code = '''
def calculate(expression):
    return eval(expression)
'''

    report = scan_code(tmp_path, code, UnsafeExecEvalRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC105"
    assert report.findings[0].cwe_id == "CWE-95"


def test_safe_eval_constant(tmp_path):
    code = '''
def calculate():
    return eval("1 + 1")
'''

    report = scan_code(tmp_path, code, UnsafeExecEvalRule)

    assert len(report.findings) == 0

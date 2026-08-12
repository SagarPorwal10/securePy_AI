from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules.hardcoded_secret import HardcodedSecretRule


def test_detect_hardcoded_secret(tmp_path):
    code = '''
password = "admin123"
'''

    file_path = tmp_path / "vulnerable.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(file_path))

    assert report.files_scanned == 1
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.rule_id == "SEC101"
    assert finding.cwe_id == "CWE-798"
    assert finding.line_number == 2


def test_ignore_normal_variable(tmp_path):
    code = '''
username = "sagar"
'''

    file_path = tmp_path / "safe.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(file_path))

    assert len(report.findings) == 0


def test_scan_directory(tmp_path):
    vulnerable_file = tmp_path / "vulnerable.py"
    safe_file = tmp_path / "safe.py"

    vulnerable_file.write_text(
        'api_key = "AKIA923848239482394"',
        encoding="utf-8",
    )

    safe_file.write_text(
        'username = "sagar"',
        encoding="utf-8",
    )

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(tmp_path))

    assert report.files_scanned == 2
    assert len(report.findings) == 1
    assert report.findings[0].file_path.endswith("vulnerable.py")

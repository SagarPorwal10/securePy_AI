import json, tempfile
from pathlib import Path

from securepy_ai.benchmark import load_dataset, BenchmarkRunner
from securepy_ai.remediator.patch_validator import PatchValidator
from securepy_ai.models import PatchCandidate, VulnerabilityFinding, Severity

with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp) / 'cwe_89_001'
    d.mkdir()
    (d / 'metadata.json').write_text(json.dumps({'id': 'cwe89_001', 'cwe': 'CWE-89', 'rule_id': 'SEC102', 'severity': 'Critical', 'vuln_type': 'SQL Injection'}))
    vuln_code = 'def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query).fetchone()\n'
    bad_code = 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return db.execute(query).fetchone()\n'
    fix_code = 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n    return db.execute(query, (user_id,)).fetchone()\n'
    (d / 'vulnerable.py').write_text(vuln_code)
    (d / 'expected_fix.py').write_text(fix_code)
    (d / 'bad_fix.py').write_text(bad_code)
    
    cases = load_dataset(tmp)
    runner = BenchmarkRunner()
    results = runner.run(cases)
    r = results[0]
    print('bad_checks:', r.get('bad_checks'))
    print('bad_rejected_full:', r.get('bad_rejected_full'))
    
    # Manual validation
    finding = VulnerabilityFinding(rule_id='SEC102', vuln_type='SQL Injection', cwe_id='CWE-89',
        severity=Severity.HIGH, file_path='test.py', line_number=2, code_snippet='', description='test')
    bad = PatchCandidate(model='oracle', prompt_used='', original_code=vuln_code,
                         patched_code=bad_code, raw_response='', latency_ms=0.0, success=True)
    v = PatchValidator().validate(finding, bad)
    print('syntax_valid:', v.syntax_valid)
    print('logic_preserved:', v.logic_preserved)
    print('vuln_fixed:', v.vuln_fixed)
    print('no_new_vulns:', v.no_new_vulns)
    print('passed:', v.passed)
    print('confidence_score:', v.confidence_score)

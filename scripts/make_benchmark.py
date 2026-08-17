#!/usr/bin/env python3
import json
from pathlib import Path

CASES = [
    # CWE-89
    {"dir": "cwe_89_001", "meta": {"id": "cwe89_001", "cwe": "CWE-89", "rule_id": "SEC102", "severity": "Critical", "vuln_type": "SQL Injection"},
     "vuln": 'def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query).fetchone()\n',
     "fix": 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n    return db.execute(query, (user_id,)).fetchone()\n',
     "bad": 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return db.execute(query).fetchone()\n'},
    {"dir": "cwe_89_002", "meta": {"id": "cwe89_002", "cwe": "CWE-89", "rule_id": "SEC102", "severity": "Critical", "vuln_type": "SQL Injection"},
     "vuln": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = \'%s\'" % name\n    return conn.execute(sql)\n',
     "fix": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = ?"\n    return conn.execute(sql, (name,))\n',
     "bad": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = \'" + name + "\'"\n    return conn.execute(sql)\n'},
    # CWE-798
    {"dir": "cwe_798_001", "meta": {"id": "cwe798_001", "cwe": "CWE-798", "rule_id": "SEC101", "severity": "High", "vuln_type": "Hardcoded Secret"},
     "vuln": 'API_KEY = "AKIA923848239482394"\n',
     "fix": 'import os\nAPI_KEY = os.environ.get("API_KEY")\n',
     "bad": 'API_KEY = "AKIA923848239482394"  # TODO move to env\n'},
    {"dir": "cwe_798_002", "meta": {"id": "cwe798_002", "cwe": "CWE-798", "rule_id": "SEC101", "severity": "High", "vuln_type": "Hardcoded Secret"},
     "vuln": 'db_password = "supersecret123"\n',
     "fix": 'import os\ndb_password = os.environ.get("DB_PASSWORD")\n',
     "bad": 'db_password = "supersecret123"  # rotate later\n'},
    # CWE-78
    {"dir": "cwe_78_001", "meta": {"id": "cwe78_001", "cwe": "CWE-78", "rule_id": "SEC103", "severity": "High", "vuln_type": "Command Injection"},
     "vuln": 'import os\ndef ping_host(host):\n    os.system("ping -c 1 " + host)\n',
     "fix": 'import subprocess\ndef ping_host(host):\n    subprocess.run(["ping", "-c", "1", host], check=True)\n',
     "bad": 'import os\ndef ping_host(host):\n    os.system("ping -c 1 " + host + " -W 2")\n'},
    {"dir": "cwe_78_002", "meta": {"id": "cwe78_002", "cwe": "CWE-78", "rule_id": "SEC103", "severity": "High", "vuln_type": "Command Injection"},
     "vuln": 'import os\ndef tail_log(path):\n    os.system("tail " + path)\n',
     "fix": 'import subprocess\ndef tail_log(path):\n    subprocess.run(["tail", path], check=True)\n',
     "bad": 'import os\ndef tail_log(path):\n    os.system("tail -n 20 " + path)\n'},
    # CWE-502
    {"dir": "cwe_502_001", "meta": {"id": "cwe502_001", "cwe": "CWE-502", "rule_id": "SEC104", "severity": "High", "vuln_type": "Insecure Deserialization"},
     "vuln": 'import pickle\ndef load_session(blob):\n    return pickle.loads(blob)\n',
     "fix": 'import json\ndef load_session(blob):\n    return json.loads(blob)\n',
     "bad": 'import pickle\ndef load_session(blob):\n    return pickle.loads(blob)  # validated upstream\n'},
    {"dir": "cwe_502_002", "meta": {"id": "cwe502_002", "cwe": "CWE-502", "rule_id": "SEC104", "severity": "High", "vuln_type": "Insecure Deserialization"},
     "vuln": 'import pickle\ndef restore_state(data):\n    return pickle.loads(data)\n',
     "fix": 'import json\ndef restore_state(data):\n    return json.loads(data)\n',
     "bad": 'import pickle\ndef restore_state(data):\n    return pickle.loads(data)  # trusted source\n'},
    # CWE-95
    {"dir": "cwe_95_001", "meta": {"id": "cwe95_001", "cwe": "CWE-95", "rule_id": "SEC105", "severity": "High", "vuln_type": "Unsafe Dynamic Execution"},
     "vuln": 'def calculate(expr):\n    return eval(expr)\n',
     "fix": 'import ast\ndef calculate(expr):\n    return ast.literal_eval(expr)\n',
     "bad": 'def calculate(expr):\n    return eval(expr, {"__builtins__": {}}, {})\n'},
    {"dir": "cwe_95_002", "meta": {"id": "cwe95_002", "cwe": "CWE-95", "rule_id": "SEC105", "severity": "High", "vuln_type": "Unsafe Dynamic Execution"},
     "vuln": 'def run_formula(formula):\n    return eval(formula)\n',
     "fix": 'import ast\ndef run_formula(formula):\n    return ast.literal_eval(formula)\n',
     "bad": 'def run_formula(formula):\n    return eval(formula)\n'},
]


def main():
    root = Path("benchmark")
    for case in CASES:
        d = root / case["dir"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "metadata.json").write_text(json.dumps(case["meta"], indent=2), encoding="utf-8")
        (d / "vulnerable.py").write_text(case["vuln"], encoding="utf-8")
        (d / "expected_fix.py").write_text(case["fix"], encoding="utf-8")
        (d / "bad_fix.py").write_text(case["bad"], encoding="utf-8")
    print(f"Created {len(CASES)} benchmark cases under benchmark/")


if __name__ == "__main__":
    main()

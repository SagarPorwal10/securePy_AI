import json

from securepy_ai.benchmark import (
    BenchmarkRunner, ablation_table, aggregate_metrics, load_dataset,
)


def make_dataset(tmp_path):
    d = tmp_path / "cwe_89_001"
    d.mkdir(parents=True)
    (d / "metadata.json").write_text(json.dumps(
        {"id": "cwe89_001", "cwe": "CWE-89", "rule_id": "SEC102",
         "severity": "Critical", "vuln_type": "SQL Injection"}), encoding="utf-8")
    (d / "vulnerable.py").write_text(
        'def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '    return db.execute(query).fetchone()\n', encoding="utf-8")
    (d / "expected_fix.py").write_text(
        'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n'
        '    return db.execute(query, (user_id,)).fetchone()\n', encoding="utf-8")
    (d / "bad_fix.py").write_text(
        'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n'
        '    return db.execute(query).fetchone()\n', encoding="utf-8")
    return load_dataset(str(tmp_path))


def test_detection_and_validation(tmp_path):
    results = BenchmarkRunner().run(make_dataset(tmp_path))
    r = results[0]
    assert r["detected"] is True
    assert r["fp_on_fix"] is False
    assert r["oracle_valid"] is True
    assert r["orig_rejected"] is True
    assert r["bad_rejected_full"] is True


def test_ablation_shows_rescan_contribution(tmp_path):
    results = BenchmarkRunner().run(make_dataset(tmp_path))
    ab = ablation_table(results)
    assert ab[0]["rejection_rate"] == 0.0   # V1 syntax only accepts the bad patch
    assert ab[2]["rejection_rate"] == 1.0   # V3 adds re-scan and rejects it


def test_aggregate_metrics(tmp_path):
    metrics = aggregate_metrics(BenchmarkRunner().run(make_dataset(tmp_path)))
    assert metrics["total_cases"] == 1
    assert metrics["detection_recall"] == 1.0
    assert metrics["oracle_accept_rate"] == 1.0

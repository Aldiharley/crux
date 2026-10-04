import json
import subprocess
import sys


def test_emit_json(tmp_path):
    inp = tmp_path / "f.json"
    inp.write_text(json.dumps([{"id": "n1", "tool": "nuclei", "rule_id": "sqli", "severity": "HIGH",
                                "title": "SQLi", "message": "m", "url": "https://a/x",
                                "category": "DAST"}]))
    out = tmp_path / "q.json"
    subprocess.run([sys.executable, "-m", "crux", "--input", str(inp), "--mock",
                    "--emit-json", str(out), "--audit", str(tmp_path / "a.jsonl"),
                    "--out", str(tmp_path / "r.md")],
                   check=True, cwd="M:/Projects/crux")
    items = json.loads(out.read_text())
    assert items and "verdict" in items[0] and "finding" in items[0]
    assert items[0]["finding"]["url"] == "https://a/x"
    assert items[0]["finding"]["category"] == "DAST"

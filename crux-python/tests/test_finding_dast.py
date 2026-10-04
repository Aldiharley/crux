from crux.models import Finding


def test_url_finding():
    f = Finding.parse({"id": "n1", "tool": "nuclei", "rule_id": "r", "severity": "HIGH",
                       "title": "t", "message": "m", "url": "https://a/p", "category": "DAST"})
    assert f.url == "https://a/p" and f.locus() == "https://a/p"


def test_sast_finding_still_parses():
    f = Finding.parse({"id": "s1", "tool": "semgrep", "rule_id": "r", "severity": "HIGH",
                       "title": "t", "message": "m", "file": "path.py", "line": 10})
    assert f.url == "" and f.locus() == "path.py:10"
    assert f.category.value == "SAST"


def test_url_included_in_content_hash():
    base = {"id": "n1", "tool": "nuclei", "rule_id": "r", "severity": "HIGH",
            "title": "t", "message": "m", "category": "DAST"}
    a = Finding.parse({**base, "url": "https://a/p"})
    b = Finding.parse({**base, "url": "https://a/q"})
    assert a.content_hash() != b.content_hash()

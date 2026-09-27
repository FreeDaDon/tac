from pathlib import Path

from core.security.secret_scan import (
    analyze_file,
    fingerprint,
    parse_allowlist,
    redact,
    scan_text,
    shannon_entropy,
)

# Built by concatenation so this test file never contains a literal token.
FAKE_GH = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_ANT = "sk-" + "ant-" + "api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"
FAKE_OAI = "sk-" + "proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12"
FAKE_SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
FAKE_AWS = "AKIA" + "FAKEFAKEFAKE1234"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def rules(text: str) -> list[str]:
    return [m.rule_id for m in scan_text(text)]


def test_provider_patterns():
    assert rules(f"key = '{FAKE_AWS}'") == ["SECRET-AWS-ACCESS-KEY"]
    assert rules(f"GH={FAKE_GH}") == ["SECRET-GITHUB-TOKEN"]
    assert rules(f"x {FAKE_ANT}") == ["SECRET-ANTHROPIC-KEY"]
    assert rules(f"x {FAKE_OAI}") == ["SECRET-OPENAI-KEY"]
    assert rules(f"x {FAKE_SLACK}") == ["SECRET-SLACK-TOKEN"]
    assert rules(PEM) == ["SECRET-PRIVATE-KEY"]


def test_generic_entropy_rule():
    assert rules('db_password = "' + "q8Zr7Lk2" + 'Vw9Xp4Tn6Yb3"') == ["SECRET-GENERIC-HIGH-ENTROPY"]
    assert rules('api_key = "aaaaaaaaaaaaaaaaaaaa"') == []          # low entropy
    assert rules('TOKEN_KEY = "tac-dashboard-token"') == []         # identifier, single char class
    assert rules('api_key = "your_api_key_placeholder_1"') == []    # placeholder
    # provider match is not double-reported by the generic rule
    assert rules(f'aws_access_key = "{FAKE_AWS}"') == ["SECRET-AWS-ACCESS-KEY"]


def test_entropy_redact_fingerprint():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert round(shannon_entropy("abcd"), 3) == 2.0
    assert redact(FAKE_AWS) == "AKIA…(20 chars)"
    assert len(fingerprint(FAKE_AWS)) == 16


def test_allowlist_parsing():
    allow = parse_allowlist("# comment\ncore/fixtures/**\nfingerprint:ABCDEF0123456789  # trailing\n\n")
    assert allow.path_globs == ("core/fixtures/**",)
    assert allow.allows("core/fixtures/swe/x.py", "zzz")
    assert allow.allows("src/x.py", "abcdef0123456789")
    assert not allow.allows("src/x.py", "zzz")


def test_sample_repo_detects_planted_secrets_without_allowlist(fixtures):
    report = analyze_file(fixtures / "swe" / "sample_repo", use_allowlist=False)
    assert report.pack == "swe" and report.tool == "secret_scan"
    found = {(f.rule_id, f.location) for f in report.findings}
    assert found == {("SECRET-AWS-ACCESS-KEY", "src/config.py:4"),
                     ("SECRET-GENERIC-HIGH-ENTROPY", "src/client.py:2")}
    assert report.metrics["files_skipped"] == 1  # logo.bin (binary)
    for f in report.findings:
        dumped = f.model_dump_json()
        assert "FAKEFAKEFAKE1234" not in dumped and "Vw9Xp4Tn6Yb3" not in dumped
    aws = next(f for f in report.findings if f.rule_id == "SECRET-AWS-ACCESS-KEY")
    assert aws.evidence["redacted"] == "AKIA…(20 chars)" and aws.evidence["length"] == 20


def test_repo_allowlist_suppresses_fixtures(fixtures):
    report = analyze_file(fixtures / "swe" / "sample_repo")
    assert report.findings == []
    assert report.metrics["suppressed"] == 2
    assert report.metrics["allowlist"].endswith(".secretsallow")


def test_skip_dirs_and_fingerprint_allowlist(tmp_path: Path):
    for rel in (".git/config", "node_modules/p/i.js", ".venv/x.py", "trees/wt/a.py", "agent/runs/r1/o.txt",
                "dist/b.js", ".mypy_cache/c.json"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"k = '{FAKE_AWS}'\n")
    (tmp_path / "agent" / "keep.py").write_text(f"k = '{FAKE_AWS}'\n")
    (tmp_path / "clean.py").write_text("print('hi')\n")
    report = analyze_file(tmp_path, use_allowlist=False)
    assert [f.location for f in report.findings] == ["agent/keep.py:1"]

    (tmp_path / ".secretsallow").write_text(f"fingerprint:{fingerprint(FAKE_AWS)}\n")
    report = analyze_file(tmp_path)
    assert report.findings == [] and report.metrics["suppressed"] == 1


def test_clean_directory(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\nTOKEN = os.environ['TOKEN']\n")
    assert analyze_file(tmp_path, use_allowlist=False).findings == []

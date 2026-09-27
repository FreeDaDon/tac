from core.security.sanitize import (
    analyze_file,
    cap_length,
    escape_html,
    escape_markdown,
    find_suspicious_unicode,
    markdown_code,
    sanitize_untrusted,
    strip_control_chars,
)


def test_strip_control_and_bidi():
    text = "ok\x00\x1b[31m\u202eevil\u200b\nnext\tline\x7f"
    assert strip_control_chars(text) == "ok[31mevil\nnext\tline"
    assert strip_control_chars("a\nb\tc", keep_newlines=False) == "a b c"


def test_cap_length():
    assert cap_length("short", 10) == "short"
    capped = cap_length("x" * 100, 20)
    assert len(capped) == 20 and capped.endswith("…[truncated]")
    assert len(sanitize_untrusted("y" * 50_000)) == 10_000


def test_escape_markdown_neutralizes_markup():
    out = escape_markdown("a|b `c` <script>x</script>\n# head *em* [l](u)")
    assert "<" not in out and ">" not in out
    assert "\\|" in out and "\\`" in out and "\\*" in out and "\\[" in out
    assert "\n" not in out
    assert escape_markdown("# title").startswith("\\#")


def test_markdown_code_fence():
    assert markdown_code("plain") == "`plain`"
    assert markdown_code("has `tick`") == "`` has `tick` ``"
    fenced = markdown_code("a ``b`` c")
    assert fenced.startswith("```") and fenced.endswith("```")


def test_escape_html():
    assert escape_html("<a href='x'>&") == "&lt;a href=&#x27;x&#x27;&gt;&amp;"


def test_find_suspicious_unicode():
    hits = find_suspicious_unicode("a\u202eb\u200bc")
    assert [i for i, _ in hits] == [1, 3]
    assert hits[0][1] == "RIGHT-TO-LEFT OVERRIDE"
    assert find_suspicious_unicode("plain ascii") == []


def test_analyze_file_trojan_source(fixtures):
    report = analyze_file(fixtures / "swe" / "trojan_source.py")
    assert [(f.rule_id, f.location.rsplit(":", 1)[1]) for f in report.findings] == [
        ("SWE-BIDI", "3"), ("SWE-ZERO-WIDTH", "5")]
    assert report.findings[0].severity == "high"


def test_analyze_clean_file(fixtures):
    assert analyze_file(fixtures / "swe" / "sample_repo" / "src" / "app.py").findings == []


def test_analyze_directory(fixtures):
    report = analyze_file(fixtures / "swe")
    assert [f.location for f in report.findings] == ["trojan_source.py:3", "trojan_source.py:5"]
    assert report.metrics["files_scanned"] >= 5

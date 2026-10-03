import pytest
from analyzer import analyze, MAX_LINES


def msgs(code):
    return [i["message"] for i in analyze(code)["issues"]]


def test_detects_eval():
    assert any("eval" in m for m in msgs("x = eval(input())"))


def test_hardcoded_secret_and_autofix():
    r = analyze('password = "abc123"')
    assert "os.environ" in r["fixed_code"]


def test_bare_except_and_pass():
    r = msgs("try:\n    x = 1\nexcept:\n    pass\n")
    assert any("Bare except" in m for m in r) and any("ignore" in m for m in r)


def test_missing_error_handling():
    assert any("error handling missing" in m for m in msgs("f = open('a.txt')"))


def test_missing_tests():
    assert analyze("def add(a, b):\n    return a + b\n")["test_suggestion"]


def test_syntax_error_reported():
    assert analyze("def (:")["issues"][0]["category"] == "syntax"


def test_empty_rejected():
    with pytest.raises(ValueError):
        analyze("   ")


def test_line_limit():
    with pytest.raises(ValueError):
        analyze("x = 1\n" * (MAX_LINES + 1))

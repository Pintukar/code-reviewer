"""Static code reviewer.
User ka code kabhi RUN nahi hota - sirf ast.parse + regex se padha jata hai."""
import ast
import re
from dataclasses import dataclass, asdict

MAX_LINES = 10_000
MAX_CHARS = 1_000_000


@dataclass
class Issue:
    line: int
    severity: str   # high / medium / low
    category: str   # security / error-handling / tests / bug / syntax
    message: str
    fix: str
    code: str = ""


R = re.compile
# (regex, severity, category, message, auto-replacement or None, hint)
RULES = [
    (R(r"\beval\("), "high", "security", "eval() se arbitrary code execute ho sakta hai.", "ast.literal_eval(", "ast.literal_eval(value) use karo (import ast)."),
    (R(r"\bexec\("), "high", "security", "exec() dangerous hai - code injection ka risk.", None, "exec() hatao; logic ko functions me likho."),
    (R(r"\bos\.system\("), "high", "security", "os.system() se command injection ho sakta hai.", None, 'subprocess.run(["cmd", "arg"], check=True) use karo.'),
    (R(r"shell\s*=\s*True"), "high", "security", "shell=True command injection ka risk badhata hai.", "shell=False", "shell=False rakho aur args ki list do."),
    (R(r"\bpickle\.loads?\("), "high", "security", "pickle untrusted data par code chala sakta hai.", None, "json.loads() use karo."),
    (R(r"\byaml\.load\("), "high", "security", "yaml.load() unsafe hai.", "yaml.safe_load(", "yaml.safe_load(...) use karo."),
    (R(r"hashlib\.(md5|sha1)\("), "medium", "security", "MD5/SHA1 weak hain. Passwords ke liye bcrypt/argon2 use karo.", "hashlib.sha256(", "hashlib.sha256(...) ya passwords ke liye bcrypt."),
    (R(r"verify\s*=\s*False"), "high", "security", "SSL verification band hai (MITM attack possible).", "verify=True", "verify=True rakho."),
    (R(r"(\w*(?:password|passwd|secret|api_key|token)\w*)\s*=\s*[\"'][^\"']+[\"']", re.I), "high", "security", "Hardcoded secret mila. Code leak = secret leak.", r'\1 = os.environ.get("\1")', 'os.environ.get("NAME") use karo (import os).'),
    (R(r"\.execute\(\s*(f[\"']|.*[\"']\s*(%|\+)|.*\.format\()"), "high", "security", "SQL injection risk: query string jodi ja rahi hai.", None, 'cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))'),
    (R(r"debug\s*=\s*True"), "medium", "security", "Debug mode production me secrets leak karta hai.", "debug=False", "debug=False rakho."),
    (R(r"tempfile\.mktemp\("), "medium", "security", "mktemp() race-condition wala hai.", "tempfile.mkstemp(", "tempfile.mkstemp() ya NamedTemporaryFile use karo."),
    (R(r"\bexcept\s*:"), "medium", "error-handling", "Bare except har error (Ctrl+C bhi) pakad leta hai.", "except Exception as exc:", "except Exception as exc: aur error log karo."),
    (R(r"\brequests\.(get|post|put|delete|patch)\((?!.*timeout)"), "medium", "error-handling", "requests me timeout nahi - program hamesha ke liye atak sakta hai.", None, "requests.get(url, timeout=10) likho."),
    (R(r"\bint\(\s*input\("), "medium", "error-handling", "Galat input par ValueError crash karega.", None, "try: n = int(input()) except ValueError: print('Number daalo')"),
    (R(r"^\s*assert\b"), "low", "bug", "assert python -O me hat jata hai; validation ke liye mat use karo.", None, "if not cond: raise ValueError('...')"),
    (R(r"\brandom\.(random|randint|choice)\("), "low", "security", "random module security tokens ke liye safe nahi.", None, "Tokens ke liye secrets module use karo."),
]

RISKY_CALLS = {
    "open": "File na mile / permission na ho to crash hoga.",
    "int": "Invalid value par ValueError aayega.",
    "float": "Invalid value par ValueError aayega.",
    "json.loads": "Invalid JSON par JSONDecodeError aayega.",
    "json.load": "Invalid JSON par JSONDecodeError aayega.",
    "requests.get": "Network error par exception aayega.",
    "requests.post": "Network error par exception aayega.",
}


def _name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _ast_checks(tree, add):
    covered = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.handlers:
            for stmt in node.body:
                covered.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
            for h in node.handlers:
                if all(isinstance(s, ast.Pass) for s in h.body):
                    add(h.lineno, "medium", "error-handling", "Error chup-chaap ignore ho raha hai (except: pass).",
                        "logging.exception('Operation failed')  # pass ki jagah")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults + node.args.kw_defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    add(node.lineno, "medium", "bug", "Mutable default argument - calls ke beech share hota hai.",
                        "def f(x=None):\n    if x is None:\n        x = []")
        if isinstance(node, ast.Call) and node.lineno not in covered:
            n = _name(node.func)
            if n in RISKY_CALLS:
                add(node.lineno, "medium", "error-handling", f"{n}() par error handling missing. {RISKY_CALLS[n]}",
                    f"try:\n    ...{n}(...)\nexcept Exception as exc:\n    logging.error('%s', exc)")


def _test_checks(tree, add):
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and not n.name.startswith("_")]
    has_tests = any(isinstance(n, ast.FunctionDef) and n.name.startswith("test_") for n in ast.walk(tree)) or any(
        isinstance(n, (ast.Import, ast.ImportFrom)) and "pytest" in ast.dump(n) or "unittest" in ast.dump(n)
        for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)))
    if has_tests or not funcs:
        return ""
    out = ["import pytest", "from your_module import *", ""]
    for f in funcs:
        add(f.lineno, "low", "tests", f"'{f.name}' ka koi test nahi mila.", f"def test_{f.name}_basic(): ...")
        out += [f"def test_{f.name}_normal():", f"    assert {f.name}(...) == ...  # TODO", "",
                f"def test_{f.name}_invalid_input():", "    with pytest.raises(Exception):", f"        {f.name}(None)", ""]
    return "\n".join(out)


def analyze(code: str) -> dict:
    if not isinstance(code, str) or not code.strip():
        raise ValueError("Code khali hai.")
    if len(code) > MAX_CHARS:
        raise ValueError("Code bahut bada hai.")
    lines = code.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"Maximum {MAX_LINES} lines allowed ({len(lines)} mili).")

    issues, seen = [], set()

    def add(line, sev, cat, msg, fix):
        if (line, msg) not in seen:
            seen.add((line, msg))
            issues.append(Issue(line, sev, cat, msg, fix, lines[line - 1].rstrip() if 0 < line <= len(lines) else ""))

    fixed = list(lines)
    for i, text in enumerate(lines, 1):
        if text.lstrip().startswith("#"):
            continue
        for rx, sev, cat, msg, repl, hint in RULES:
            if rx.search(fixed[i - 1]):
                if repl:
                    fixed[i - 1] = rx.sub(repl, fixed[i - 1])
                    add(i, sev, cat, msg, fixed[i - 1].strip())
                else:
                    add(i, sev, cat, msg, hint)

    test_suggestion = ""
    try:
        tree = ast.parse(code)
        _ast_checks(tree, add)
        test_suggestion = _test_checks(tree, add)
    except SyntaxError as e:
        add(e.lineno or 1, "high", "syntax", f"Syntax error: {e.msg}", "Is line ka syntax theek karo.")
    except (ValueError, RecursionError):
        add(1, "high", "syntax", "Code parse nahi ho paya.", "Code check karo.")

    issues.sort(key=lambda x: (x.line, x.severity))
    summary = {s: sum(1 for x in issues if x.severity == s) for s in ("high", "medium", "low")}
    return {"total_lines": len(lines), "summary": summary, "issues": [asdict(x) for x in issues],
            "test_suggestion": test_suggestion, "fixed_code": "\n".join(fixed)}

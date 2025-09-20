from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
import ast
import re


@dataclass
class Tool:
    """
    Represents a reusable tool function with metadata for agent execution.

    Attributes:
        name: Tool name (defaults to the function name).
        description: What the tool does (from the function docstring).
        func: The underlying callable.
        arguments: List of (name, type) pairs from the function signature.
        outputs: Return type name of the function.
    """

    name: str
    description: str
    func: Callable[..., Any]
    arguments: List[Tuple[str, str]]
    outputs: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # Allow direct invocation
        return self.func(*args, **kwargs)


def tool(func: Callable[..., Any]) -> Tool:
    """Decorator that converts a function into a Tool with rich metadata."""
    signature = inspect.signature(func)

    arguments: List[Tuple[str, str]] = []
    for param in signature.parameters.values():
        annotation = param.annotation
        ann_name = (
            annotation.__name__
            if hasattr(annotation, "__name__")
            else (str(annotation) if annotation is not inspect._empty else "Any")
        )
        arguments.append((param.name, ann_name))

    return_annotation = signature.return_annotation
    outputs = (
        return_annotation.__name__
        if hasattr(return_annotation, "__name__") and return_annotation is not inspect._empty
        else (str(return_annotation) if return_annotation is not inspect._empty else "Any")
    )

    description = func.__doc__ or "No description provided."
    name = func.__name__

    return Tool(
        name=name,
        description=description,
        func=func,
        arguments=arguments,
        outputs=outputs,
    )


# ---------- Tools ----------


@tool
def python_static_vuln_scan(file_path: str) -> Dict[str, Any]:
    """
    Scan a Python file for common insecure patterns using AST and regex heuristics.

    Detects (non-exhaustive):
      - eval/exec usage
      - os.system, subprocess.* with shell=True or untrusted strings
      - pickle/cPickle loads, yaml.load (unsafe)
      - requests with verify=False (SSL disabled)
      - weak hashes (md5, sha1)
      - potential SQL injection via string concatenation/format in cursor.execute
      - hardcoded secrets (basic regex heuristics)
      - broad exception handlers (bare except)
    Returns dict: { 'success': bool, 'file': str, 'findings': [ {rule, severity, message, line, snippet} ], 'summary': {...} }
    """
    findings: List[Dict[str, Any]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        return {"success": False, "file": file_path, "error": f"read error: {e}"}

    try:
        tree = ast.parse(source)
    except Exception as e:
        return {"success": False, "file": file_path, "error": f"parse error: {e}"}

    lines = source.splitlines()

    def add(rule: str, severity: str, message: str, node: ast.AST):
        lineno = getattr(node, 'lineno', None)
        snippet = lines[lineno - 1].strip() if lineno and 1 <= lineno <= len(lines) else ""
        findings.append({
            "rule": rule,
            "severity": severity,
            "message": message,
            "line": lineno,
            "snippet": snippet,
        })

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            # eval/exec
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                add("PY-EVAL-EXEC", "high", f"Use of {node.func.id} is dangerous", node)

            # os.system
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                attr = node.func.attr
                if mod == "os" and attr == "system":
                    add("PY-OS-SYSTEM", "medium", "Use of os.system can be unsafe; prefer subprocess without shell", node)

            # subprocess.* with shell=True
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                attr = node.func.attr
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        add("PY-SUBPROCESS-SHELL", "high", f"subprocess.{attr} with shell=True is dangerous", node)

            # pickle / yaml.load
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
                attr = node.func.attr
                if mod in {"pickle", "cPickle"} and attr in {"load", "loads"}:
                    add("PY-PICKLE-LOAD", "high", f"{mod}.{attr} can execute code when loading untrusted data", node)
                if mod == "yaml" and attr == "load":
                    add("PY-YAML-LOAD", "high", "yaml.load is unsafe; use yaml.safe_load", node)

            # requests verify=False
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        add("PY-REQUESTS-VERIFY", "medium", "requests with verify=False disables SSL verification", node)

            # weak hashes
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in {"md5", "sha1"}:
                    add("PY-WEAK-HASH", "medium", f"hashlib.{node.func.attr} is weak; use sha256/sha3", node)

            # potential SQL injection: cursor.execute with string concat/format
            if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                if node.args:
                    s = node.args[0]
                    if isinstance(s, ast.BinOp) and isinstance(s.op, (ast.Add,)):
                        add("PY-SQLI", "high", "string concatenation in SQL execute", node)
                    if isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute) and s.func.attr in {"format", "join"}:
                        add("PY-SQLI", "high", "string formatting used to build SQL", node)
                    if isinstance(s, ast.JoinedStr):  # f"...{var}..."
                        add("PY-SQLI", "high", "f-string used to build SQL", node)

            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler):
            if node.type is None:
                add("PY-BARE-EXCEPT", "low", "Bare except: catches all exceptions", node)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign):
            # Hardcoded secrets (heuristic)
            secret_names = re.compile(r"(api[_-]?key|secret|token|passwd|password|access[_-]?key)", re.I)
            for target in node.targets:
                name = None
                if isinstance(target, ast.Name):
                    name = target.id
                elif isinstance(target, ast.Attribute):
                    name = target.attr
                if name and secret_names.search(name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 6:
                        add("PY-HARDCODED-SECRET", "high", f"Hardcoded secret in variable '{name}'", node)
            self.generic_visit(node)

    Visitor().visit(tree)

    severity_order = {"high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda f: (-severity_order.get(f["severity"], 0), f.get("line") or 0))
    summary = {
        "total": len(findings),
        "by_severity": {
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        },
    }

    return {"success": True, "file": file_path, "findings": findings, "summary": summary}

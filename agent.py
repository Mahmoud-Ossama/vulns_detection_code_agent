import argparse
import sys
from typing import Any, Dict, List, Optional

from tools import python_static_vuln_scan


def format_vuln_report(scan_result: Dict[str, Any]) -> str:
	if not scan_result.get("success"):
		return f"Scan failed for {scan_result.get('file')}: {scan_result.get('error')}"
	lines = []
	file_path = scan_result.get("file")
	summary = scan_result.get("summary", {})
	lines.append(f"Vulnerability Scan Report: {file_path}")
	lines.append("")
	lines.append(f"Total findings: {summary.get('total', 0)}")
	by_sev = summary.get("by_severity", {})
	lines.append(f" - High: {by_sev.get('high', 0)}  Medium: {by_sev.get('medium', 0)}  Low: {by_sev.get('low', 0)}")
	lines.append("")
	for i, f in enumerate(scan_result.get("findings", []), 1):
		lines.append(f"[{i}] {f.get('severity','').upper()} {f.get('rule')} @ line {f.get('line')}")
		lines.append(f"    Message: {f.get('message')}")
		snippet = f.get("snippet") or ""
		if snippet:
			lines.append(f"    Code: {snippet}")
		lines.append("")
	return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
	parser = argparse.ArgumentParser(description="Static Python vulnerability scanner")
	parser.add_argument("--scan-file", required=True, help="Path to a Python file to scan")
	args = parser.parse_args(argv)

	res = python_static_vuln_scan(args.scan_file)
	print(format_vuln_report(res))
	return 0


if __name__ == "__main__":
	sys.exit(main())


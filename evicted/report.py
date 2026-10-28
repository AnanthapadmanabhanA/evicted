"""Render a Report as text or JSON."""
from __future__ import annotations

import json

from . import __version__
from .model import Report, Status

_STATUS_TAG = {
    Status.VULNERABLE: "VULNERABLE",
    Status.OK: "ok",
    Status.SKIPPED: "skipped",
    Status.ERROR: "error",
}


def to_dict(report: Report) -> dict:
    ordered = report.sorted_findings()
    worst = ordered[0].severity.value if ordered and ordered[0].is_vulnerable else None
    return {
        "tool": "evicted",
        "version": __version__,
        "target": report.target,
        "summary": {
            "checks_run": len(report.findings),
            "vulnerable": len(report.vulnerable),
            "worst_severity": worst,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status.value,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in ordered
        ],
    }


def to_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2)


def to_text(report: Report) -> str:
    findings = report.sorted_findings()
    n_vuln = len(report.vulnerable)
    lines = [
        f"evicted {__version__}  --  target: {report.target}",
        f"{len(findings)} checks run, {n_vuln} vulnerable",
        "",
    ]
    for f in findings:
        tag = _STATUS_TAG[f.status]
        head = f"[{tag}] {f.id}  {f.title}"
        if f.status.value == "vulnerable":
            head += f"  ({f.severity.value.upper()})"
        lines.append(head)
        if f.detail:
            lines.append(f"      {f.detail}")
    if n_vuln:
        lines += ["", "Access that should have ended did not. Fix server-side, then re-run."]
    else:
        lines += ["", "No access-removal failures found by these checks."]
    return "\n".join(lines)

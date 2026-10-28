"""Command line entry point.

    evicted scan                 # run against the built-in vulnerable mock cloud
    evicted scan --target mock-hardened
    evicted scan --json out.json

Pointing evicted at a real vendor means writing a CloudAdapter and
wiring it in here; see docs/methodology.md. By design the shipped CLI
only targets the in-process mock, so it never touches a real account
unless you add an adapter yourself.
"""
from __future__ import annotations

import argparse
import sys

from . import __version__, report
from .engine import Engine, EngineConfig
from .mock import HARDENED_PROFILE, VULNERABLE_PROFILE, build_mock_scenario

_TARGETS = {
    "mock-vulnerable": VULNERABLE_PROFILE,
    "mock-hardened": HARDENED_PROFILE,
}


def _run_mock(profile) -> report.Report:
    adapter, owner, guest, third, device, second = build_mock_scenario(profile)
    engine = Engine(adapter)
    cfg = EngineConfig(owner=owner, guest=guest, device=device,
                       third_party=third, second_device=second)
    return engine.run(cfg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evicted",
        description="Does a removed user actually lose access to a smart-home device?")
    parser.add_argument("--version", action="version", version=f"evicted {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the lifecycle checks against a target")
    scan.add_argument("--target", default="mock-vulnerable",
                      choices=sorted(_TARGETS), help="which target to test (default: mock-vulnerable)")
    scan.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
    scan.add_argument("--quiet", action="store_true", help="don't print the text report")

    args = parser.parse_args(argv)

    rep = _run_mock(_TARGETS[args.target])
    if not args.quiet:
        print(report.to_text(rep))
    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json(rep))
    # exit code 1 when the target has at least one access-removal failure
    return 1 if rep.vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())

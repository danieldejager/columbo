"""Fail-closed wrapper: runs a check command with a timeout and requires a pass report.

Usage: python3 gate.py --timeout SECONDS --report OUT.json -- CMD ...
Exit 0 only if CMD exits 0 in time AND the report exists with status "pass".
"""
import argparse
import json
import os
import subprocess
import sys


def gate(cmd, report, timeout):
    if os.path.exists(report):
        os.remove(report)
    try:
        rc = subprocess.run(cmd, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print("FAIL: check timed out after %s s" % timeout)
        return 1
    except Exception as e:  # fail closed on anything
        print("FAIL: check could not run: %s" % e)
        return 1
    try:
        with open(report) as f:
            data = json.load(f)
    except Exception:
        print("FAIL: check report missing or unreadable")
        return 1
    if rc != 0 or not isinstance(data, dict) or data.get("status") != "pass":
        print("FAIL: check did not pass (exit %s)" % rc)
        return 1
    print("PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--report", required=True)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        print("FAIL: no command")
        return 1
    return gate(cmd, a.report, a.timeout)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Keep one required check stable when a selected matrix is skipped."""

import json
import os
import sys


REQUIRED = {"line-limit", "qa-select", "go-checks"}
CONDITIONAL = {
    "cross-build": "agent_cross_platform",
    "installed-container": "agent_installed_container",
}


def validate(jobs):
    if not isinstance(jobs, dict) or set(jobs) != REQUIRED | set(CONDITIONAL):
        raise ValueError("CI results do not contain the complete expected job set")
    if any(not isinstance(job, dict) for job in jobs.values()):
        raise ValueError("CI job results are invalid")
    for name in REQUIRED:
        if jobs[name].get("result") != "success":
            raise ValueError(f"Required CI job did not pass: {name}")
    outputs = jobs["qa-select"].get("outputs")
    names = ("checks_required", *CONDITIONAL.values())
    if not isinstance(outputs, dict) or any(outputs.get(name) not in ("true", "false") for name in names):
        raise ValueError("QA selection did not produce a valid check plan")
    checks = outputs["checks_required"] == "true"
    for name, selection in CONDITIONAL.items():
        selected = outputs[selection] == "true"
        if selected and not checks:
            raise ValueError("QA selection requests a contract while disabling checks")
        allowed = ("success",) if selected else ("success", "skipped")
        if jobs[name].get("result") not in allowed:
            raise ValueError(f"Selected CI job failed or a skip was not allowed: {name}")


def main():
    try:
        validate(json.loads(os.environ["NEEDS_JSON"]))
    except (KeyError, ValueError) as error:
        print(f"CI failed: {error}", file=sys.stderr)
        return 1
    print("All required CI checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

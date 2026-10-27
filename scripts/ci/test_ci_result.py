"""Prevent missing matrix checks or failed jobs from permitting a merge."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("ci_result", Path(__file__).with_name("check-ci-result.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def results(selected=True):
    jobs = {name: {"result": "success"} for name in GATE.REQUIRED | set(GATE.CONDITIONAL)}
    choice = "true" if selected else "false"
    jobs["qa-select"]["outputs"] = {
        "checks_required": choice,
        "agent_cross_platform": choice,
        "agent_installed_container": choice,
    }
    if not selected:
        for name in GATE.CONDITIONAL:
            jobs[name]["result"] = "skipped"
    return jobs


class CIResultTests(unittest.TestCase):
    def test_successful_selected_checks_and_documentation_skips_pass(self):
        GATE.validate(results())
        GATE.validate(results(selected=False))

    def test_each_failure_or_cancellation_blocks_even_when_not_selected(self):
        for selected in (True, False):
            for name in results():
                for outcome in ("failure", "cancelled"):
                    with self.subTest(selected=selected, job=name, outcome=outcome):
                        jobs = results(selected)
                        jobs[name]["result"] = outcome
                        with self.assertRaises(ValueError):
                            GATE.validate(jobs)

    def test_required_job_skips_block_including_selected_matrix(self):
        for name in results():
            with self.subTest(job=name):
                jobs = results()
                jobs[name]["result"] = "skipped"
                with self.assertRaises(ValueError):
                    GATE.validate(jobs)

    def test_only_unselected_contracts_may_skip(self):
        for name, selection in GATE.CONDITIONAL.items():
            jobs = results()
            jobs["qa-select"]["outputs"][selection] = "false"
            jobs[name]["result"] = "skipped"
            GATE.validate(jobs)

    def test_missing_or_invalid_plan_cannot_authorize_skips(self):
        for name in results()["qa-select"]["outputs"]:
            for value in (None, "", "TRUE", True):
                with self.subTest(output=name, value=value):
                    jobs = results(False)
                    jobs["qa-select"]["outputs"][name] = value
                    with self.assertRaises(ValueError):
                        GATE.validate(jobs)
        jobs = results(False)
        jobs["qa-select"]["outputs"]["agent_cross_platform"] = "true"
        with self.assertRaises(ValueError):
            GATE.validate(jobs)

    def test_missing_job_cannot_disappear_from_the_gate(self):
        for name in results():
            with self.subTest(job=name):
                jobs = results(False)
                del jobs[name]
                with self.assertRaises(ValueError):
                    GATE.validate(jobs)


if __name__ == "__main__":
    unittest.main()

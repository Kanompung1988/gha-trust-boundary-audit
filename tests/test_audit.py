import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.audit import analyze, events, main, parse_yaml, permission_writes, scan

ROOT = Path(__file__).resolve().parents[1]
GOOD = (ROOT / "examples" / "safe.yml").read_text(encoding="utf-8")
BAD = (ROOT / "examples" / "unsafe.yml").read_text(encoding="utf-8")


class WorkflowTests(unittest.TestCase):
    def rules(self, source):
        return [f.rule for f in analyze(source, "x.yml")]

    def test_trigger_preserved(self):
        obj, _ = parse_yaml("on: [push]\njobs: {}\n")
        self.assertEqual(obj["on"], ["push"])

    def test_mapping_trigger(self):
        self.assertEqual(events({"push": None, "pull_request": None}), {"push", "pull_request"})

    def test_scalar_trigger(self):
        self.assertEqual(events("push"), {"push"})

    def test_permission_writes(self):
        self.assertTrue(permission_writes({"contents": "write"}))
        self.assertFalse(permission_writes({"contents": "read"}))

    def test_clean_fixture_no_high(self):
        self.assertFalse([x for x in analyze(GOOD, "safe.yml") if x.severity in ("high", "critical")])

    def test_bad_fixture_unsafe_event(self):
        self.assertIn("GHA004", self.rules(BAD))

    def test_bad_fixture_pr_checkout(self):
        self.assertIn("GHA006", self.rules(BAD))

    def test_bad_fixture_write_all(self):
        self.assertIn("GHA002", self.rules(BAD))

    def test_action_sha_pinning(self):
        valid_sha = "a" * 40
        example = f"on: push\npermissions: {{contents: read}}\njobs:\n  lint:\n    steps:\n      - uses: actions/checkout@{valid_sha}\n"
        self.assertNotIn("GHA003", self.rules(example))

    def test_unpinned_tag_detection(self):
        self.assertIn("GHA003", self.rules(GOOD))

    def test_secret_expression_detection(self):
        x = "on: push\npermissions: {}\njobs:\n  x:\n    steps:\n      - run: echo ${{ secrets.API_TOKEN }}\n"
        self.assertIn("GHA005", self.rules(x))

    def test_env_forwarding_not_shell_interpolation(self):
        x = "on: pull_request\npermissions: {}\njobs:\n  x:\n    steps:\n      - run: 'printf %s \"$TITLE\"'\n        env:\n          TITLE: '${{ github.event.pull_request.title }}'\n"
        self.assertNotIn("GHA004", self.rules(x))

    def test_pr_target_default_checkout_no_critical(self):
        x = "on: pull_request_target\npermissions: {}\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ok\n"
        self.assertNotIn("GHA006", self.rules(x))

    def test_critical_requires_later_run(self):
        x = "on: pull_request_target\npermissions: {}\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: '${{ github.event.pull_request.head.sha }}'\n"
        self.assertNotIn("GHA006", self.rules(x))

    def test_exact_line_number(self):
        hit = [f for f in analyze(BAD, "unsafe.yml") if f.rule == "GHA004"][0]
        self.assertEqual(hit.line, 12)

    def test_duplicate_yaml_keys_rejected(self):
        with self.assertRaises(ValueError):
            parse_yaml("jobs: {}\njobs: {}\n")

    def test_bad_root_rejected(self):
        with self.assertRaises(ValueError):
            analyze("[]", "x.yml")

    def test_cli_json_exit_code(self):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "audit.py"), str(ROOT / "examples" / "unsafe.yml"), "--format", "json"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)
        self.assertGreater(json.loads(out.stdout)["count"], 0)

    def test_cli_safe_exit_code(self):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "audit.py"), str(ROOT / "examples" / "safe.yml")], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)

    def test_empty_repository_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".github" / "workflows").mkdir(parents=True)
            self.assertEqual(scan(Path(tmp)), [])

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "w.yml"
            link.symlink_to(ROOT / "examples" / "safe.yml")
            with self.assertRaises(ValueError):
                scan(link)

    def test_file_cap_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "huge.yml"
            p.write_text(" " * 512001)
            with self.assertRaises(ValueError):
                scan(p)

    def test_local_action_not_pinned(self):
        x = "on: push\npermissions: {}\njobs:\n  x:\n    steps:\n      - uses: ./tool\n"
        self.assertNotIn("GHA003", self.rules(x))


if __name__ == "__main__":
    unittest.main()

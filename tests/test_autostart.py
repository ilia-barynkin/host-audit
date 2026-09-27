"""Autostart report publication tests; never scan a host or invoke systemd."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "autostart" / "run_audit.py"
SPEC = importlib.util.spec_from_file_location("autostart_runner", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
DEFAULT = object()


class AutostartTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.script = self.root / "audit with spaces; $literal.py"

    @staticmethod
    def report(code):
        return {
            "exit_code": code, "findings": [], "gaps": [],
            "recent_failed_logins": {"status": "ok", "entries": []},
        }

    def command(self, code=0, payload=DEFAULT, create=True, mode=None):
        def run(argv, **kwargs):
            output = Path(argv[argv.index("--output") + 1])
            self.assertEqual(output.parent, self.state / "reports")
            self.assertNotEqual(output.suffix, ".json")
            if create:
                value = self.report(code) if payload is DEFAULT else payload
                text = value if isinstance(value, str) else json.dumps(value)
                with output.open("x", encoding="utf-8") as stream:
                    stream.write(text)
                if mode is not None:
                    output.chmod(mode)
            return subprocess.CompletedProcess(argv, code)
        return run

    def invoke(self, effect=None):
        effect = self.command() if effect is None else effect
        with mock.patch.object(runner.subprocess, "run", side_effect=effect) as command:
            with contextlib.redirect_stdout(io.StringIO()):
                result = runner.run_audit(self.state, self.script)
        return result, command

    def preserve_latest_on_failure(self, effect, exceptions=(ValueError, OSError)):
        self.invoke()
        latest = self.state / "latest.json"
        target = os.readlink(latest)
        data = latest.read_bytes()
        with self.assertRaises(exceptions):
            self.invoke(effect)
        self.assertEqual(os.readlink(latest), target)
        self.assertEqual(latest.read_bytes(), data)
        self.assertEqual(len(list((self.state / "reports").glob("*.json"))), 1)

    def test_success_publishes_private_json_and_relative_latest_link(self):
        code, _ = self.invoke()
        self.assertEqual(code, 0)
        latest = self.state / "latest.json"
        self.assertTrue(latest.is_symlink())
        target = Path(os.readlink(latest))
        self.assertFalse(target.is_absolute())
        self.assertEqual(target.parent, Path("reports"))
        self.assertEqual(target.suffix, ".json")
        self.assertEqual(json.loads(latest.read_text()), self.report(0))
        for path, mode in ((self.state, 0o700), (self.state / "reports", 0o700),
                           (latest.resolve(), 0o600)):
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(list((self.state / "reports").glob("*.partial")), [])

    def test_findings_and_coverage_gaps_are_valid_published_reports(self):
        for code in (1, 2):
            with self.subTest(code=code):
                result, _ = self.invoke(self.command(code))
                self.assertEqual(result, code)
                self.assertEqual(json.loads((self.state / "latest.json").read_text()), self.report(code))

    def test_repeated_runs_keep_unique_reports_and_previous_history(self):
        self.invoke()
        reports = self.state / "reports"
        original = {path: path.read_bytes() for path in reports.glob("*.json")}
        old = reports / "report-20000101T000000.000000Z-historical.json"
        old.write_text('{"historical": true}\n')
        original[old] = old.read_bytes()
        self.invoke(self.command(1))
        self.invoke(self.command(2))
        self.assertEqual(len(list(reports.glob("*.json"))), 4)
        for path, data in original.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["exit_code"], 2)

    def test_invocation_uses_isolated_python_literal_arguments_and_timeout(self):
        _, command = self.invoke()
        command.assert_called_once()
        args = command.call_args.args[0]
        self.assertEqual(args[:7], [
            sys.executable, "-I", "-B", str(self.script), "--format", "json", "--output",
        ])
        self.assertEqual(len(args), 8)
        self.assertEqual(command.call_args.kwargs["timeout"], 150)
        self.assertIs(command.call_args.kwargs["check"], False)
        self.assertFalse(command.call_args.kwargs.get("shell", False))
        self.assertNotEqual(command.call_args.kwargs.get("stdout"), subprocess.PIPE)

    def test_malformed_incomplete_or_mismatched_json_keeps_previous_latest(self):
        for payload in ('{"exit_code":', [], {}, self.report(2),
                        {**self.report(0), "recent_failed_logins": None}):
            with self.subTest(payload=payload):
                # Each case gets a separate state tree and an established report.
                self.state = self.root / ("state-%d" % len(list(self.root.iterdir())))
                self.preserve_latest_on_failure(self.command(payload=payload))

    def test_success_exit_without_a_report_keeps_previous_latest(self):
        self.preserve_latest_on_failure(self.command(create=False))

    def test_failure_exit_does_not_publish_even_well_formed_output(self):
        self.preserve_latest_on_failure(self.command(code=3))

    def test_timeout_keeps_previous_latest(self):
        self.preserve_latest_on_failure(
            subprocess.TimeoutExpired([str(self.script)], 150),
            exceptions=(subprocess.TimeoutExpired,),
        )

    def test_symlink_state_reports_or_ancestor_is_rejected_before_execution(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        for position in ("state", "reports", "ancestor"):
            with self.subTest(position=position):
                self.state = self.root / ("state-" + position)
                if position == "state":
                    self.state.symlink_to(outside, target_is_directory=True)
                elif position == "reports":
                    self.state.mkdir(mode=0o700)
                    (self.state / "reports").symlink_to(outside, target_is_directory=True)
                else:
                    ancestor = self.root / "linked-parent"
                    ancestor.symlink_to(outside, target_is_directory=True)
                    self.state = ancestor / "state"
                with mock.patch.object(runner.subprocess, "run") as command:
                    with self.assertRaises((ValueError, OSError)):
                        runner.run_audit(self.state, self.script)
                command.assert_not_called()
                self.assertEqual(list(outside.iterdir()), [])

    def test_public_existing_report_directory_is_rejected(self):
        for position in ("state", "reports"):
            with self.subTest(position=position):
                self.state = self.root / ("state-" + position)
                self.state.mkdir(mode=0o700)
                unsafe = self.state
                if position == "reports":
                    unsafe = self.state / "reports"
                    unsafe.mkdir(mode=0o700)
                unsafe.chmod(0o755)
                with mock.patch.object(runner.subprocess, "run") as command:
                    with self.assertRaises((ValueError, OSError)):
                        runner.run_audit(self.state, self.script)
                command.assert_not_called()

    def test_public_report_permissions_prevent_publication(self):
        self.preserve_latest_on_failure(self.command(mode=0o644))

    def test_nonregular_report_is_rejected_without_following_symlink(self):
        outside = self.root / "outside.json"
        outside.write_text(json.dumps(self.report(0)))
        outside.chmod(0o600)
        original = outside.read_bytes()
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                self.state = self.root / ("state-" + kind)

                def command(argv, **kwargs):
                    output = Path(argv[argv.index("--output") + 1])
                    if kind == "symlink":
                        output.symlink_to(outside)
                    else:
                        os.mkfifo(output, 0o600)
                    return subprocess.CompletedProcess(argv, 0)

                self.preserve_latest_on_failure(command)
                self.assertEqual(outside.read_bytes(), original)

    def test_umask_is_restored_after_success_and_failure(self):
        previous = os.umask(0o022)
        try:
            self.invoke()
            actual = os.umask(0o022)
            self.assertEqual(actual, 0o022)
            with self.assertRaises(ValueError):
                self.invoke(self.command(code=3))
            actual = os.umask(0o022)
            self.assertEqual(actual, 0o022)
        finally:
            os.umask(previous)


if __name__ == "__main__":
    unittest.main()

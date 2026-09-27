"""Failed-login report tests using synthetic files and command output only."""

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import host_audit


class RecentFailedLoginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.btmp = self.root / "btmp"
        self.btmp.write_bytes(b"")
        self.audit = host_audit.Audit()
        patcher = mock.patch.object(host_audit, "BTMP_PATH", str(self.btmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def row(user="n", terminal="", address="0.0.0.0", at="2026-09-27T12:58:05+00:00"):
        return "%-8s\t%-12s\t%-15s\t%s\t- %s\t (00:00)\n" % (
            user, terminal, address, at, at,
        )

    def collect(self, rows="", footer=True, code=0, reason=None):
        def command(argv, **kwargs):
            selected = argv[argv.index("--file") + 1]
            descriptor = int(Path(selected).name)
            self.assertEqual(selected, "/proc/self/fd/%d" % descriptor)
            self.assertIn(descriptor, kwargs["pass_fds"])
            self.assertEqual(os.fstat(descriptor).st_ino, self.btmp.stat().st_ino)
            ending = "\n%s begins 2026-01-01T00:00:00+00:00\n" % descriptor if footer else ""
            return rows + ending, code, reason

        with mock.patch.object(host_audit, "command_path", return_value="/synthetic/lastb"), mock.patch.object(
            host_audit, "run_bounded", side_effect=command
        ) as run:
            result = self.audit.failed_logins()
        return result, run

    def test_empty_readable_log_is_successful_empty_list(self):
        result, _ = self.collect()
        self.assertEqual(result["source"], str(self.btmp))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["limit"], 50)
        self.assertEqual(result["entries"], [])
        self.assertIs(result["has_more"], False)
        self.assertEqual(self.audit.report["gaps"], [])

    def test_local_failure_with_blank_terminal_is_preserved(self):
        result, _ = self.collect(self.row())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["entries"], [{
            "user": "n", "terminal": None, "address": "0.0.0.0",
            "at": "2026-09-27T12:58:05+00:00",
        }])
        self.assertIs(result["has_more"], False)
        # A failed login is useful context, not itself a compromise finding.
        self.assertEqual(self.audit.report["findings"], [])

    def test_unicode_names_ipv6_and_record_order_are_preserved(self):
        rows = self.row("пользователь", "ssh:notty", "2001:db8::f", "2026-09-27T12:58:05+00:00")
        rows += self.row("older", "tty2", "192.0.2.10", "2026-08-01T01:02:03+00:00")
        result, _ = self.collect(rows)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([entry["user"] for entry in result["entries"]], ["пользователь", "older"])
        self.assertEqual(result["entries"][0]["address"], "2001:db8::f")
        self.assertEqual(result["entries"][0]["terminal"], "ssh:notty")
        self.assertEqual(result["entries"][1]["at"], "2026-08-01T01:02:03+00:00")

    def test_duplicate_failures_in_the_same_second_are_not_deduplicated(self):
        result, _ = self.collect(self.row() * 2)
        self.assertEqual(len(result["entries"]), 2)
        self.assertEqual(result["entries"][0], result["entries"][1])

    def test_exactly_fifty_rows_do_not_claim_more_history(self):
        result, _ = self.collect("".join(self.row("n%d" % i) for i in range(50)))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["entries"]), 50)
        self.assertIs(result["has_more"], False)

    def test_extra_row_sets_has_more_but_is_not_in_report(self):
        result, run = self.collect("".join(self.row("n%d" % i) for i in range(51)))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["entries"]), 50)
        self.assertEqual(result["entries"][0]["user"], "n0")
        self.assertEqual(result["entries"][-1]["user"], "n49")
        self.assertIs(result["has_more"], True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index("--limit") + 1], "51")
        self.assertEqual(argv[argv.index("--time-format") + 1], "iso")
        self.assertIn("--tab-separated", argv)
        self.assertIn("--fullnames", argv)
        self.assertIn("--ip", argv)
        self.assertNotIn("--since", argv)

    def test_malformed_rows_or_dates_mark_coverage_incomplete(self):
        for broken in (
            "not a lastb record\n",
            self.row(at="2026-99-27T12:58:05+00:00"),
            self.row(at="2026-09-27T12:58:05"),
        ):
            with self.subTest(broken=broken):
                self.audit = host_audit.Audit()
                result, _ = self.collect(self.row() + broken)
                self.assertEqual(result["status"], "partial")
                self.assertIsNone(result["has_more"])
                self.assertTrue(self.audit.report["gaps"])
                self.assertEqual(len(result["entries"]), 1)

    def test_missing_footer_does_not_look_like_complete_output(self):
        for rows in ("", self.row()):
            with self.subTest(rows=rows):
                self.audit = host_audit.Audit()
                result, _ = self.collect(rows, footer=False)
                self.assertNotEqual(result["status"], "ok")
                self.assertIsNone(result["has_more"])
                self.assertTrue(self.audit.report["gaps"])

    def test_failed_or_timed_out_command_does_not_trust_partial_entries(self):
        for code, reason in ((1, None), (-9, "тайм-аут команды"), (-9, "превышен лимит вывода команды")):
            with self.subTest(code=code, reason=reason):
                self.audit = host_audit.Audit()
                result, _ = self.collect(self.row(), code=code, reason=reason)
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["entries"], [])
                self.assertIsNone(result["has_more"])
                self.assertTrue(self.audit.report["gaps"])

    def test_missing_lastb_is_unavailable(self):
        with mock.patch.object(host_audit, "command_path", return_value=None), mock.patch.object(
            host_audit, "run_bounded"
        ) as run:
            result = self.audit.failed_logins()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["entries"], [])
        self.assertIsNone(result["has_more"])
        run.assert_not_called()
        self.assertTrue(self.audit.report["gaps"])

    def test_command_launch_error_closes_the_open_log(self):
        descriptors = []

        def failed_command(argv, **kwargs):
            descriptors.extend(kwargs["pass_fds"])
            raise OSError(errno.ENOEXEC, "synthetic command error")

        with mock.patch.object(host_audit, "command_path", return_value="/synthetic/lastb"), mock.patch.object(
            host_audit, "run_bounded", side_effect=failed_command
        ):
            result = self.audit.failed_logins()
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["has_more"])
        self.assertTrue(descriptors)
        for descriptor in descriptors:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_missing_or_unreadable_log_is_not_reported_as_empty_success(self):
        real_open = os.open

        def denied(path, *args, **kwargs):
            if os.fspath(path) in ("btmp", str(self.btmp)):
                raise PermissionError(errno.EACCES, "synthetic denied log")
            return real_open(path, *args, **kwargs)

        for missing in (False, True):
            self.audit = host_audit.Audit()
            if missing:
                self.btmp.unlink()
            with self.subTest(missing=missing), mock.patch.object(
                host_audit, "command_path", return_value="/synthetic/lastb"
            ), mock.patch.object(host_audit, "run_bounded") as run, mock.patch.object(
                host_audit.os, "open", side_effect=real_open if missing else denied
            ):
                result = self.audit.failed_logins()
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["entries"], [])
            self.assertIsNone(result["has_more"])
            self.assertTrue(self.audit.report["gaps"])
            run.assert_not_called()

    def test_symlink_log_is_rejected_without_starting_lastb(self):
        target = self.root / "target"
        target.write_bytes(b"synthetic private data")
        self.btmp.unlink()
        self.btmp.symlink_to(target)
        with mock.patch.object(host_audit, "command_path", return_value="/synthetic/lastb"), mock.patch.object(
            host_audit, "run_bounded"
        ) as run:
            result = self.audit.failed_logins()
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["has_more"])
        run.assert_not_called()

    def test_fifo_log_is_rejected_without_blocking(self):
        self.btmp.unlink()
        os.mkfifo(self.btmp)
        # Bound a child process so a regression cannot hang the test runner.
        code = (
            "import sys; from unittest import mock; import host_audit\n"
            "host_audit.BTMP_PATH = sys.argv[1]\n"
            "with mock.patch.object(host_audit, 'command_path', return_value='/synthetic/lastb'), "
            "mock.patch.object(host_audit, 'run_bounded') as run:\n"
            "    result = host_audit.Audit().failed_logins()\n"
            "    assert result['status'] == 'unavailable', result\n"
            "    assert result['has_more'] is None, result\n"
            "    run.assert_not_called()\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(self.btmp)],
            cwd=Path(host_audit.__file__).parent, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_recent_failed_logins_is_last_in_emitted_json(self):
        section = {
            "source": "/var/log/btmp", "status": "ok", "limit": 50,
            "entries": [], "has_more": False,
        }
        with contextlib.ExitStack() as stack:
            for name in ("accounts", "persistence", "processes", "network", "ssh_log"):
                stack.enter_context(mock.patch.object(host_audit.Audit, name))
            failed = stack.enter_context(mock.patch.object(host_audit.Audit, "failed_logins", return_value=section))
            stack.enter_context(mock.patch.object(host_audit.os, "geteuid", return_value=0))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(host_audit.main(["--format", "json"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(list(report)[-1], "recent_failed_logins")
        self.assertEqual(report["recent_failed_logins"], section)
        self.assertNotIn("since_previous_check", output.getvalue())
        failed.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

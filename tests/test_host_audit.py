"""Synthetic-only regression tests; these never audit the machine running them."""

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import host_audit


class FileSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_regular_file_byte_limit_including_empty_file(self):
        path = self.root / "input"
        path.write_bytes(b"1234")
        self.assertEqual(host_audit.read_regular(path, 4), b"1234")
        with self.assertRaises(OSError) as raised:
            host_audit.read_regular(path, 3)
        self.assertEqual(raised.exception.errno, errno.EFBIG)
        path.write_bytes(b"")
        self.assertEqual(host_audit.read_regular(path, 0), b"")

    def test_read_rejects_leaf_symlink(self):
        target = self.root / "target"
        target.write_bytes(b"private synthetic data")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            host_audit.read_regular(link)
        self.assertTrue(stat.S_ISLNK(host_audit.safe_stat(link).st_mode))

    def test_read_and_directory_listing_reject_parent_symlink(self):
        target = self.root / "target"
        target.mkdir()
        (target / "input").write_bytes(b"private synthetic data")
        (target / "directory").mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        for operation in (
            lambda: host_audit.read_regular(link / "input"),
            lambda: host_audit.safe_stat(link / "input"),
            lambda: host_audit.directory_names(link / "directory", 10),
            lambda: host_audit.directory_names(link, 10),
        ):
            with self.subTest(operation=operation), self.assertRaises(OSError):
                operation()

    def test_parent_resolution_rejects_relative_and_dot_dot_paths(self):
        for path in ("relative", str(self.root / ".." / "input")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                host_audit.read_regular(path)

    def test_fifo_rejected_without_waiting_for_a_writer(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        # A child deadline makes this test safe even if nonblocking open regresses.
        code = (
            "import errno, sys; import host_audit\n"
            "try:\n"
            "    host_audit.read_regular(sys.argv[1])\n"
            "except OSError as error:\n"
            "    sys.exit(0 if error.errno == errno.EINVAL else 1)\n"
            "sys.exit(2)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", code, str(fifo)],
            cwd=Path(host_audit.__file__).parent,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_directory_listing_reports_truncation(self):
        for name in ("a", "b", "c"):
            (self.root / name).touch()
        names, truncated = host_audit.directory_names(self.root, 2)
        self.assertEqual(len(names), 2)
        self.assertEqual(names, sorted(names))
        self.assertTrue(truncated)

    def test_report_is_private_even_with_permissive_umask(self):
        path = self.root / "report"
        previous = os.umask(0)
        try:
            host_audit.write_report(path, "synthetic report\n")
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.read_text(), "synthetic report\n")

    def test_report_never_overwrites_existing_file_or_leaf_symlink(self):
        target = self.root / "target"
        target.write_text("original")
        link = self.root / "link"
        link.symlink_to(target)
        for path in (target, link):
            with self.subTest(path=path), self.assertRaises(FileExistsError):
                host_audit.write_report(path, "replacement")
        self.assertEqual(target.read_text(), "original")
        self.assertTrue(link.is_symlink())

    def test_report_rejects_symlink_parent(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            host_audit.write_report(link / "report", "synthetic")
        self.assertFalse((target / "report").exists())


class ProcessAndOutputTests(unittest.TestCase):
    def test_process_path_boundaries_avoid_false_positives(self):
        for path in (
            "/usr/bin/python3", "/temporary/program", "/tmp-backup/program",
            "/var/tmp-old/program", "/dev/shm-backup/program",
            "/opt/tmp/program", "/usr/bin/memfd:program",
        ):
            with self.subTest(path=path):
                self.assertEqual(host_audit.process_flags(path), [])
        for path in ("/tmp/program", "/var/tmp/program", "/dev/shm/program"):
            with self.subTest(path=path):
                self.assertEqual(len(host_audit.process_flags(path)), 1)

    def test_deleted_and_memfd_processes_are_flagged(self):
        self.assertEqual(len(host_audit.process_flags("/usr/bin/program (deleted)")), 1)
        self.assertEqual(len(host_audit.process_flags("/tmp/program (deleted)")), 2)
        self.assertEqual(len(host_audit.process_flags("/memfd:program (deleted)")), 2)
        self.assertEqual(len(host_audit.process_flags("memfd:program")), 1)
        self.assertEqual(host_audit.process_flags("/usr/bin/program (deleted).bak"), [])

    def test_clean_escapes_terminal_controls_and_bidi(self):
        value = "обычный текст\x1b[31m\n\r\t\x00\x7f\u202e\u2066"
        cleaned = host_audit.clean(value)
        self.assertEqual(
            cleaned,
            "обычный текст\\u001b[31m\\u000a\\u000d\\u0009\\u0000\\u007f\\u202e\\u2066",
        )

    def test_command_output_is_bounded(self):
        output, code, reason = host_audit.run_bounded(
            [sys.executable, "-B", "-c", "import os; os.write(1, b'x' * 65536)"],
            timeout=3, limit=128,
        )
        self.assertEqual(output, "x" * 128)
        self.assertIsNotNone(reason)
        self.assertIn("лимит", reason)
        self.assertIsInstance(code, int)

    def test_command_timeout_terminates_process(self):
        started = time.monotonic()
        output, code, reason = host_audit.run_bounded(
            [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
            timeout=0.1, limit=128,
        )
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(output, "")
        self.assertLess(code, 0)
        self.assertIn("тайм-аут", reason)

    def test_command_preserves_exit_status_and_merges_stderr(self):
        output, code, reason = host_audit.run_bounded(
            [sys.executable, "-B", "-c", "import os; os.write(2, b'failure'); raise SystemExit(7)"],
            timeout=3, limit=128,
        )
        self.assertEqual((output, code, reason), ("failure", 7, None))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.audit = host_audit.Audit(days=3)

    def test_accounts_detect_uid_zero_and_empty_passwords_without_hashes(self):
        passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:0:0:admin:/home/admin:/bin/bash\n"
            "empty::1000:1000:empty:/home/empty:/bin/sh\n"
            "shadowempty:x:1001:1001:user:/home/user:/bin/sh\n"
            "legacy:$synthetic-passwd-secret:1002:1002:user:/home/legacy:/bin/sh\n"
            "broken:record\n"
        ).encode()
        shadow = (
            "root:$synthetic-shadow-secret:1:0:99999:7:::\n"
            "empty::1:0:99999:7:::\n"
            "shadowempty::1:0:99999:7:::\n"
        ).encode()
        with mock.patch.object(self.audit, "read", side_effect=lambda path: {
            "/etc/passwd": passwd, "/etc/shadow": shadow,
        }[path]):
            self.audit.accounts()
        findings = self.audit.report["findings"]
        uid_zero = [item["evidence"]["user"] for item in findings if item["code"] == "extra_uid_zero"]
        empty = [item["evidence"]["user"] for item in findings if item["code"] == "empty_password"]
        self.assertEqual(uid_zero, ["admin"])
        self.assertEqual(empty, ["empty", "shadowempty"])
        serialized = json.dumps(self.audit.report)
        self.assertNotIn("synthetic-passwd-secret", serialized)
        self.assertNotIn("synthetic-shadow-secret", serialized)
        self.assertTrue(any(gap["check"] == "accounts" for gap in self.audit.report["gaps"]))

    def test_malformed_numeric_ids_do_not_prevent_later_accounts(self):
        rows = [
            "unicode:x:²:1000:user:/home/unicode:/bin/sh",
            "oversized:x:%s:1000:user:/home/oversized:/bin/sh" % ("9" * 5000),
            "uid_overflow:x:4294967296:1000:user:/home/overflow:/bin/sh",
            "gid_overflow:x:1000:4294967296:user:/home/overflow:/bin/sh",
            "negative:x:-1:1000:user:/home/negative:/bin/sh",
            "valid:x:1000:1000:user:/home/valid:/bin/sh",
            "maximum:x:4294967295:4294967295:user:/home/maximum:/bin/sh",
        ]
        users, malformed = host_audit.parse_accounts("\n".join(rows).encode())
        self.assertEqual(malformed, 5)
        self.assertEqual([user["name"] for user in users], ["valid", "maximum"])
        self.assertEqual(users[-1]["uid"], 4294967295)
        self.assertEqual(users[-1]["gid"], 4294967295)

    def test_read_marks_a_budget_gap_without_opening_more_files(self):
        self.audit.total_bytes = host_audit.MAX_TOTAL
        with mock.patch.object(host_audit, "read_regular") as read:
            self.assertIsNone(self.audit.read("/synthetic/never-opened"))
        read.assert_not_called()
        self.assertEqual(self.audit.report["gaps"][0]["check"], "files")

    def test_repeated_oversized_reads_cannot_evade_aggregate_budget(self):
        with mock.patch.object(host_audit, "MAX_FILE", 4), mock.patch.object(
            host_audit, "MAX_TOTAL", 8
        ), mock.patch.object(
            host_audit, "read_regular", side_effect=OSError(errno.EFBIG, "synthetic oversized file")
        ) as read:
            for index in range(3):
                self.assertIsNone(self.audit.read("/synthetic/file%d" % index))
        self.assertEqual(read.call_args_list, [
            mock.call("/synthetic/file0", 4), mock.call("/synthetic/file1", 4),
        ])
        self.assertEqual(self.audit.total_bytes, 8)
        self.assertTrue(any(gap["check"] == "files" for gap in self.audit.report["gaps"]))

    def test_successful_small_read_releases_unused_allowance(self):
        with mock.patch.object(host_audit, "MAX_FILE", 4), mock.patch.object(
            host_audit, "MAX_TOTAL", 5
        ), mock.patch.object(host_audit, "read_regular", side_effect=[b"a", b"bcde"]) as read:
            self.assertEqual(self.audit.read("/synthetic/first"), b"a")
            self.assertEqual(self.audit.total_bytes, 1)
            self.assertEqual(self.audit.read("/synthetic/second"), b"bcde")
        self.assertEqual(read.call_args_list, [
            mock.call("/synthetic/first", 4), mock.call("/synthetic/second", 4),
        ])
        self.assertEqual(self.audit.total_bytes, 5)

    def test_failed_command_output_is_a_gap_not_trusted_inventory(self):
        for result in (("partial", 0, "тайм-аут команды"), ("error", 1, None)):
            audit = host_audit.Audit()
            with self.subTest(result=result), mock.patch.object(
                host_audit, "command_path", return_value="/synthetic/ss"
            ), mock.patch.object(host_audit, "run_bounded", return_value=result):
                self.assertIsNone(audit.command("ss", ["-H"]))
                self.assertEqual(audit.report["gaps"][0]["check"], "ss")

    def run_mocked(self, finding=False, gap=False, effective_uid=0):
        if finding:
            self.audit.finding("synthetic", "warning", "synthetic finding")
        if gap:
            self.audit.gap("synthetic", "synthetic gap")
        with contextlib.ExitStack() as stack:
            for name in ("accounts", "persistence", "processes", "network", "ssh_log"):
                stack.enter_context(mock.patch.object(self.audit, name))
            stack.enter_context(mock.patch.object(self.audit, "failed_logins", return_value={
                "source": "/var/log/btmp", "status": "ok", "limit": 50,
                "entries": [], "has_more": False,
            }))
            stack.enter_context(mock.patch.object(host_audit.os, "geteuid", return_value=effective_uid))
            return self.audit.run()

    def test_result_and_exit_distinguish_findings_from_coverage_gaps(self):
        for finding, gap, exit_code in ((False, False, 0), (True, False, 1),
                                        (False, True, 2), (True, True, 1)):
            self.audit = host_audit.Audit()
            with self.subTest(finding=finding, gap=gap):
                report = self.run_mocked(finding, gap)
                self.assertEqual(report["exit_code"], exit_code)
                self.assertEqual(report["result"], "review_required" if finding else "no_indicators_found")
                self.assertEqual(report["coverage"], "partial" if gap else "completed_within_scope")
                self.assertIn("finished_at", report)

    def test_nonroot_run_reports_incomplete_coverage(self):
        report = self.run_mocked(effective_uid=1000)
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["coverage"], "partial")
        self.assertEqual(report["gaps"][0]["check"], "privileges")

    def test_main_returns_report_status_without_reading_host(self):
        report = self.run_mocked(gap=True)
        with mock.patch.object(host_audit, "Audit") as audit_class, contextlib.redirect_stdout(io.StringIO()) as output:
            audit_class.return_value.run.return_value = report
            self.assertEqual(host_audit.main(["--format", "json", "--days", "3"]), 2)
        audit_class.assert_called_once_with(3)
        self.assertEqual(json.loads(output.getvalue())["exit_code"], 2)

    def test_main_report_write_failure_returns_three(self):
        report = self.run_mocked()
        with mock.patch.object(host_audit, "Audit") as audit_class, mock.patch.object(
            host_audit, "write_report", side_effect=FileExistsError("synthetic existing report")
        ), contextlib.redirect_stderr(io.StringIO()) as output:
            audit_class.return_value.run.return_value = report
            self.assertEqual(host_audit.main(["--output", "synthetic-report"]), 3)
        self.assertIn("Не удалось записать", output.getvalue())


class SSHJournalTests(unittest.TestCase):
    def test_journal_and_accepted_inventory_are_bounded(self):
        audit = host_audit.Audit(days=3)
        rows = [json.dumps({
            "MESSAGE": "Accepted publickey for synthetic from 192.0.2.1 port 1234 ssh2",
            "__REALTIME_TIMESTAMP": str(index),
        }) for index in range(60)]
        rows.append(json.dumps({"MESSAGE": "Failed password for ignored from 192.0.2.2 port 1234 ssh2"}))
        with mock.patch.object(host_audit, "MAX_LOGS", 60), mock.patch.object(
            audit, "command", return_value="\n".join(rows)
        ) as command:
            audit.ssh_log()
        inventory = audit.report["inventory"]["ssh_log"]
        self.assertEqual(inventory["sample_size"], 60)
        self.assertEqual(inventory["counts"]["accepted"], 60)
        self.assertEqual(inventory["counts"].get("failed", 0), 0)
        self.assertEqual(len(inventory["recent_accepted"]), 50)
        self.assertEqual(inventory["recent_accepted"][0]["timestamp_us"], "0")
        self.assertEqual(len(audit.report["gaps"]), 2)
        name, arguments = command.call_args.args
        self.assertEqual(name, "journalctl")
        self.assertIn("--reverse", arguments)
        self.assertEqual(arguments[arguments.index("--lines") + 1], "61")
        self.assertEqual(arguments[arguments.index("--since") + 1], "3 days ago")
        self.assertIn("--identifier=sshd", arguments)
        self.assertIn("--identifier=sshd-session", arguments)

    def test_failed_login_summary_counts_events_without_copying_raw_log(self):
        audit = host_audit.Audit()
        rows = [json.dumps({
            "MESSAGE": "Failed password for invalid user private-user from 192.0.2.%d port 1234 ssh2 private-marker" % (index % 12 + 1),
        }) for index in range(24)]
        with mock.patch.object(audit, "command", return_value="\n".join(rows)):
            audit.ssh_log()
        finding, = audit.report["findings"]
        self.assertEqual(finding["code"], "ssh_failed_logins")
        self.assertEqual(finding["evidence"]["count"], 24)
        self.assertEqual(len(finding["evidence"]["top_addresses"]), 10)
        serialized = json.dumps(audit.report)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("private-marker", serialized)

    def test_empty_unavailable_or_malformed_journal_does_not_look_complete(self):
        for output in ("", "not json", "[]", '{"MESSAGE": [65, 66]}'):
            audit = host_audit.Audit()
            with self.subTest(output=output), mock.patch.object(audit, "command", return_value=output):
                audit.ssh_log()
                self.assertTrue(audit.report["gaps"])
                self.assertEqual(audit.report["findings"], [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Run the installed audit and publish a complete, private JSON report."""

import datetime as dt
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid


def private_directory(path):
    path = Path(path).absolute()
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise ValueError("Symbolic link in report path: %s" % component)
    path.mkdir(mode=0o700, exist_ok=True)
    metadata = path.stat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ValueError("Report directory must be owned by the current user and have permissions 0700: %s" % path)
    return path


def run_audit(state_dir, audit_script):
    previous_umask = os.umask(0o077)
    try:
        state = private_directory(state_dir)
        reports = private_directory(state / "reports")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        name = "report-%s-%s" % (stamp, uuid.uuid4().hex)
        partial = reports / (name + ".partial")
        destination = reports / (name + ".json")
        completed = subprocess.run([
            sys.executable, "-I", "-B", str(audit_script),
            "--format", "json", "--output", str(partial),
        ], check=False, timeout=150)
        if completed.returncode not in (0, 1, 2):
            raise ValueError("Audit did not produce a complete report: exit code %d" % completed.returncode)
        descriptor = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size > 32 * 1024 * 1024):
                raise ValueError("Invalid report type, owner, permissions, or size")
            report = json.load(stream)
        if (not isinstance(report, dict)
                or report.get("exit_code") != completed.returncode
                or not isinstance(report.get("findings"), list)
                or not isinstance(report.get("gaps"), list)
                or not isinstance(report.get("recent_failed_logins"), dict)):
            raise ValueError("Incomplete or invalid JSON report")
        os.replace(partial, destination)
        temporary_link = state / (".latest-" + uuid.uuid4().hex)
        try:
            temporary_link.symlink_to(Path("reports") / destination.name)
            os.replace(temporary_link, state / "latest.json")
        finally:
            if temporary_link.is_symlink():
                temporary_link.unlink()
        print("Report: %s; findings=%d, gaps=%d" % (
            destination, len(report["findings"]), len(report["gaps"])), flush=True)
        return completed.returncode
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    try:
        sys.exit(run_audit("/var/lib/host-audit", "/usr/local/lib/host-audit/host_audit.py"))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Automatic audit did not complete: %s" % error, file=sys.stderr)
        sys.exit(3)

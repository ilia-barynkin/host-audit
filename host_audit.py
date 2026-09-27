#!/usr/bin/env python3
"""Read-only, bounded Linux compromise triage. Python 3.8+, standard library only."""

import argparse
import collections
import contextlib
import datetime as dt
import errno
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import unicodedata


MAX_FILE = 256 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 2000
MAX_PROCESSES = 20000
MAX_USERS = 500
MAX_COMMAND = 1024 * 1024
MAX_LOGS = 1000
MAX_FAILED_LOGINS = 50
BTMP_PATH = "/var/log/btmp"
COMMAND_TIMEOUT = 15
NOTICE = (
    "This audit looks for indicators of compromise; it does not prove the host is clean. "
    "Legitimate configuration and updates can trigger warnings. "
    "A compromised kernel, Python runtime, utilities, or logs can conceal evidence."
)
SCOPE = (
    "Checks cover local accounts, visible processes and TCP/UDP sockets, "
    "standard SSH files, selected startup directories, a sample of SSH logs, "
    "and recent failed logins from btmp. "
    "Memory, firmware, all binaries/packages, ACLs, remote account directories, "
    "and nonstandard SSH/startup paths are outside the scope. "
    "Inside a container, only the accessible portion of the system is visible."
)


def utc(timestamp=None):
    return dt.datetime.fromtimestamp(
        time.time() if timestamp is None else timestamp, dt.timezone.utc
    ).isoformat()


def clean(value):
    """Escape terminal controls, including bidi controls in attacker-owned names."""
    return "".join(
        "\\u%04x" % ord(char) if unicodedata.category(char).startswith("C") else char
        for char in str(value)
    )


@contextlib.contextmanager
def parent_fd(path):
    """Resolve each parent using directory FDs; never traverse a symlink."""
    path = os.fspath(path)
    parts = path.split("/")
    if not path.startswith("/") or ".." in parts:
        raise ValueError("An absolute path without '..' is required")
    parts = [part for part in parts if part and part != "."]
    if not parts:
        raise ValueError("The path must refer to a file or subdirectory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


def safe_stat(path):
    with parent_fd(path) as (directory, name):
        return os.stat(name, dir_fd=directory, follow_symlinks=False)


def safe_link(path):
    with parent_fd(path) as (directory, name):
        return os.readlink(name, dir_fd=directory)


def read_regular(path, limit=MAX_FILE):
    """Reject symlinks/devices/FIFOs, with a hard byte bound (also for procfs)."""
    with parent_fd(path) as (directory, name):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
        chunks = []
        size = 0
        while size <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - size))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            size += len(chunk)
        raise OSError(errno.EFBIG, "file read limit exceeded", os.fspath(path))
    finally:
        os.close(descriptor)


def directory_names(path, limit):
    with parent_fd(path) as (directory, name):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= limit:
                    return sorted(names), True
                names.append(entry.name)
        return sorted(names), False
    finally:
        os.close(descriptor)


def run_bounded(argv, timeout=COMMAND_TIMEOUT, limit=MAX_COMMAND, pass_fds=()):
    """Capture bounded output without a shell, pager, inherited PATH or LD_* vars."""
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC",
        "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "cat", "PAGER": "cat",
    }
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, env=environment, start_new_session=True,
        pass_fds=pass_fds,
    )
    chunks = []
    size = 0
    reason = None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "command timed out"
                    break
                if not selector.select(remaining):
                    reason = "command timed out"
                    break
                chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - size))
                if not chunk:
                    try:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        reason = "command timed out"
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    reason = "command output limit exceeded"
                    break
    finally:
        if process.poll() is None or reason:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
    output = b"".join(chunks)[:limit].decode("utf-8", "replace")
    return output, process.returncode, reason


def command_path(name):
    for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def process_flags(executable):
    flags = []
    path = executable[:-10] if executable.endswith(" (deleted)") else executable
    if path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        flags.append("executable located in a temporary directory")
    if path.startswith(("/memfd:", "memfd:")):
        flags.append("executable in memfd; a legitimate loader may be responsible")
    if executable.endswith(" (deleted)"):
        flags.append("executable deleted; this may be the result of an update")
    return flags


def parse_accounts(data):
    users = []
    malformed = 0
    for line in data.decode("utf-8", "replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7 or not all(re.fullmatch(r"[0-9]{1,10}", field) for field in fields[2:4]):
            malformed += 1
            continue
        if any(int(field) > 4294967295 for field in fields[2:4]):
            malformed += 1
            continue
        name, password, uid, gid, _, home, shell = fields
        users.append({"name": name, "uid": int(uid), "gid": int(gid),
                      "home": home, "shell": shell, "empty_password": password == ""})
    return users, malformed


class Audit:
    def __init__(self, days=7):
        self.days = days
        self.started = time.time()
        self.total_bytes = 0
        self.visited = set()
        self.users = []
        self.report = {
            "schema_version": 1, "started_at": utc(self.started),
            "host": os.uname().nodename, "kernel": os.uname().release,
            "effective_uid": os.geteuid(), "notice": NOTICE, "scope": SCOPE,
            "findings": [], "gaps": [], "inventory": {},
        }

    def finding(self, code, severity, message, **evidence):
        self.report["findings"].append({
            "code": code, "severity": severity, "message": message, "evidence": evidence,
        })

    def gap(self, check, detail):
        item = {"check": check, "detail": str(detail)}
        if item not in self.report["gaps"]:
            self.report["gaps"].append(item)

    def read(self, path, optional=False):
        if self.total_bytes >= MAX_TOTAL:
            self.gap("files", "Total file read limit reached")
            return None
        allowance = min(MAX_FILE, MAX_TOTAL - self.total_bytes)
        # Reserve the allowance even on oversized or failed reads: failures must
        # not allow repeated reads to evade the aggregate budget.
        self.total_bytes += allowance
        try:
            data = read_regular(path, allowance)
            self.total_bytes -= allowance - len(data)
            return data
        except FileNotFoundError:
            if not optional:
                self.gap(str(path), "File not found")
        except (OSError, ValueError) as error:
            self.gap(str(path), error)
        return None

    def accounts(self):
        data = self.read("/etc/passwd")
        if data is None:
            return
        users, malformed = parse_accounts(data)
        if malformed:
            self.gap("accounts", "Malformed passwd entries: %d" % malformed)
        if len(users) > MAX_USERS:
            self.gap("accounts", "Account limit reached: %d" % MAX_USERS)
        self.users = users[:MAX_USERS]
        for user in self.users:
            if user["uid"] == 0 and user["name"] != "root":
                self.finding("extra_uid_zero", "high", "Additional account with UID 0",
                             user=user["name"])
        shadow = self.read("/etc/shadow")
        empty = {user["name"] for user in self.users if user["empty_password"]}
        if shadow is not None:
            for line in shadow.decode("utf-8", "replace").splitlines():
                fields = line.split(":")
                if len(fields) == 9 and fields[1] == "":
                    empty.add(fields[0])
        for name in sorted(empty):
            self.finding("empty_password", "high",
                         "Empty password field; login availability depends on PAM/SSH and account expiration",
                         user=name)
        self.report["inventory"]["accounts"] = [
            {key: value for key, value in user.items() if key != "empty_password"}
            for user in self.users
        ]

    def inspect_path(self, path, owners=(0,), scan=False, private=False):
        if path in self.visited:
            return None
        if len(self.visited) >= MAX_FILES:
            self.gap("files", "File and directory limit reached: %d" % MAX_FILES)
            return None
        self.visited.add(path)
        try:
            metadata = safe_stat(path)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            self.gap(path, error)
            return None
        mode = stat.S_IMODE(metadata.st_mode)
        item = {"path": path, "uid": metadata.st_uid, "gid": metadata.st_gid,
                "mode": "%04o" % mode,
                "mtime_ns": metadata.st_mtime_ns,
                "recent": metadata.st_mtime >= self.started - self.days * 86400}
        self.report["inventory"].setdefault("files", []).append(item)
        if stat.S_ISLNK(metadata.st_mode):
            item["type"] = "symlink"
            try:
                item["target"] = safe_link(path)
            except OSError as error:
                self.gap(path, error)
            # systemd enablement and masking use symlinks routinely.
            self.gap(path, "Symbolic link: target contents were not checked")
            return metadata
        item["type"] = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        if metadata.st_uid not in owners:
            self.finding("unexpected_owner", "warning", "Unexpected owner of a sensitive path",
                         path=path, uid=metadata.st_uid, expected_uids=list(owners))
        if mode & 0o022:
            self.finding("writable_sensitive_path", "high" if mode & 0o002 else "warning",
                         "Sensitive path is writable by the group or other users",
                         path=path, mode=item["mode"])
        if private and mode & 0o007:
            self.finding("exposed_shadow", "high", "Password file is accessible to other users",
                         path=path, mode=item["mode"])
        if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
            self.gap(path, "Special file: contents were not read")
        if scan and stat.S_ISREG(metadata.st_mode):
            data = self.read(path)
            if data is not None:
                item["sha256"] = hashlib.sha256(data).hexdigest()
                lines = [line.strip() for line in data.decode("utf-8", "replace").splitlines()
                         if line.strip() and not line.lstrip().startswith(("#", ";"))]
                if path == "/etc/ld.so.preload" and lines:
                    self.finding("global_preload", "warning",
                                 "Global LD_PRELOAD is active; verify the origin of the libraries",
                                 path=path)
                if any(re.search(r"(?:^|[\s=\"'])/(?:tmp|var/tmp|dev/shm)/", line)
                       for line in lines):
                    self.finding("persistence_temp_reference", "warning",
                                 "An access/startup file references a temporary directory; "
                                 "this may be a working directory or a legitimate setting",
                                 path=path)
                if any(re.search(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:/bin/)?(?:ba)?sh\b", line)
                       for line in lines):
                    self.finding("download_pipe_shell", "warning",
                                 "An access/startup file pipes a download to a shell",
                                 path=path)
        return metadata

    def tree(self, path, owners=(0,), depth=0):
        metadata = self.inspect_path(path, owners, scan=True)
        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            return
        if depth >= 6:
            self.gap(path, "Directory traversal depth limit reached")
            return
        try:
            names, truncated = directory_names(path, max(0, MAX_FILES - len(self.visited)))
            if truncated:
                self.gap(path, "Directory entry limit reached")
            for name in names:
                self.tree(os.path.join(path, name), owners, depth + 1)
        except (OSError, ValueError) as error:
            self.gap(path, error)

    def persistence(self):
        for path in ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"):
            self.inspect_path(path, private=path.endswith("shadow"))
        for path in (
            "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d", "/etc/ld.so.preload", "/etc/crontab",
            "/etc/anacrontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
            "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
            "/etc/systemd/system", "/run/systemd/system", "/etc/systemd/user",
            "/usr/local/lib/systemd/system", "/etc/init.d", "/etc/rc.local",
            "/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d",
            "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/init",
            "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc",
            "/etc/environment", "/etc/rc.d", "/etc/xdg/autostart",
        ):
            self.tree(path)
        for user in self.users:
            home = user["home"]
            if not home.startswith("/") or ".." in home.split("/"):
                self.gap("home:" + user["name"], "Invalid home directory")
                continue
            if home in ("/", "/nonexistent", "/dev/null"):
                continue
            owners = (0, user["uid"])
            self.inspect_path(home, owners)
            for suffix in (".ssh", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/rc",
                           ".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc"):
                self.inspect_path(os.path.join(home, suffix), owners, scan=suffix != ".ssh")
            for suffix in (".config/systemd/user", ".config/autostart"):
                self.tree(os.path.join(home, suffix), owners)

    def processes(self):
        checked = 0
        vanished = 0
        denied = 0
        suspects = []
        try:
            names, truncated = directory_names("/proc", MAX_PROCESSES + 256)
            pids = [name for name in names if name.isdigit()]
            if truncated or len(pids) > MAX_PROCESSES:
                self.gap("processes", "Process limit reached")
            for pid in pids[:MAX_PROCESSES]:
                try:
                    status = read_regular("/proc/%s/status" % pid, 65536).decode("utf-8", "replace")
                    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                    # Kernel threads and zombies legitimately have no exe link.
                    if fields.get("Kthread", "").strip() == "1" or fields.get("State", "").strip().startswith("Z"):
                        continue
                    executable = safe_link("/proc/%s/exe" % pid)
                    effective_uid = int(fields["Uid"].split()[1])
                    checked += 1
                    reasons = process_flags(executable)
                    if reasons:
                        entry = {"pid": int(pid), "effective_uid": effective_uid,
                                 "name": fields.get("Name", "").strip(), "exe": executable,
                                 "reasons": reasons}
                        suspects.append(entry)
                        self.finding("unusual_process", "warning",
                                     "Verify the origin of the process executable", **entry)
                except FileNotFoundError:
                    vanished += 1
                except PermissionError:
                    denied += 1
                except (OSError, ValueError, KeyError, IndexError) as error:
                    self.gap("process:" + pid, error)
        except OSError as error:
            self.gap("processes", error)
        if denied:
            self.gap("processes", "Cannot access %d processes" % denied)
        if vanished:
            self.gap("processes", "%d processes exited or have no accessible exe link" % vanished)
        self.report["inventory"]["processes"] = {
            "checked": checked, "inaccessible": denied, "vanished_or_no_exe": vanished,
            "suspects": suspects,
        }

    def command(self, name, args):
        executable = command_path(name)
        if executable is None:
            self.gap(name, "Utility not found")
            return None
        try:
            output, code, reason = run_bounded([executable] + args)
        except OSError as error:
            self.gap(name, error)
            return None
        if reason or code:
            self.gap(name, reason or "Exit code %d" % code)
            return None
        return output

    def network(self):
        sockets = {}
        for name, args in (("listeners_tcp_udp", ["-H", "-lntup"]),
                           ("connected_tcp", ["-H", "-ntp", "state", "established"])):
            output = self.command("ss", args)
            if output is not None:
                lines = output.splitlines()
                if len(lines) > 300:
                    self.gap("network:" + name, "Only the first 300 sockets are included in the report")
                sockets[name] = lines[:300]
        self.report["inventory"]["network"] = sockets

    def ssh_log(self):
        output = self.command("journalctl", [
            "--no-pager", "--quiet", "--output=json", "--reverse",
            "--since", "%d days ago" % self.days, "--lines", str(MAX_LOGS + 1),
            "--identifier=sshd", "--identifier=sshd-session",
        ])
        if output is None:
            return
        rows = output.splitlines()
        if not rows:
            self.gap("ssh_log", "No accessible sshd journal entries; text logs and their rotated archives were not checked")
        if len(rows) > MAX_LOGS:
            self.gap("ssh_log", "Sample limited to the most recent %d entries" % MAX_LOGS)
        counts = collections.Counter()
        accepted = []
        failures = collections.Counter()
        parsed = 0
        for row in rows[:MAX_LOGS]:
            try:
                record = json.loads(row)
                message = record.get("MESSAGE", "")
                if not isinstance(message, str):
                    raise ValueError("MESSAGE is not a string")
                parsed += 1
                success = re.search(r"Accepted (\S+) for (\S+) from (\S+) port \d+", message)
                failure = re.search(r"Failed \S+ for (?:invalid user )?\S+ from (\S+) port \d+", message)
                if success:
                    counts["accepted"] += 1
                    if len(accepted) < 50:
                        accepted.append({"method": success[1], "user": success[2], "address": success[3],
                                         "timestamp_us": record.get("__REALTIME_TIMESTAMP")})
                if failure:
                    counts["failed"] += 1
                    failures[failure[1]] += 1
                if "Invalid user " in message:
                    counts["invalid_user"] += 1
            except (ValueError, TypeError, AttributeError):
                self.gap("ssh_log", "Some journal entries could not be parsed")
        if rows and not parsed:
            self.gap("ssh_log", "Could not read journal entries")
        if counts["accepted"] > len(accepted):
            self.gap("ssh_log", "Only the 50 most recent successful logins are included")
        if counts["failed"] >= 20:
            self.finding("ssh_failed_logins", "warning",
                         "Many failed SSH logins in the sample; attempts do not prove a successful compromise",
                         count=counts["failed"], top_addresses=failures.most_common(10))
        self.report["inventory"]["ssh_log"] = {
            "source": "journalctl: sshd, sshd-session", "requested_days": self.days,
            "sample_size": parsed, "counts": dict(counts), "recent_accepted": accepted,
        }

    def failed_logins(self):
        result = {"source": BTMP_PATH, "status": "unavailable",
                  "limit": MAX_FAILED_LOGINS, "entries": [], "has_more": None}
        try:
            executable = command_path("lastb")
            if executable is None:
                raise ValueError("The lastb utility was not found")
            # Pass an already opened regular file, avoiding symlink/FIFO races.
            with parent_fd(BTMP_PATH) as (directory, name):
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=directory,
                )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("btmp is not a regular file")
                output, code, reason = run_bounded([
                    executable, "--file", "/proc/self/fd/%d" % descriptor,
                    "--tab-separated", "--time-format", "iso", "--fullnames", "--ip",
                    "--limit", str(MAX_FAILED_LOGINS + 1),
                ], pass_fds=(descriptor,))
            finally:
                os.close(descriptor)
            if reason or code:
                raise ValueError(reason or "lastb exited with code %d; support for --tab-separated is required" % code)
        except (OSError, ValueError) as error:
            result["error"] = str(error)
            self.gap("recent_failed_logins", error)
            return result

        entries = []
        malformed = False
        footer_seen = False
        for row in output.splitlines():
            if not row.strip():
                continue
            if row.startswith("%d begins " % descriptor):
                try:
                    dt.datetime.fromisoformat(row.split(" begins ", 1)[1].strip())
                    footer_seen = True
                    continue
                except ValueError:
                    pass
            fields = [field.strip() for field in row.split("\t")]
            try:
                if len(fields) != 6 or footer_seen:
                    raise ValueError("Invalid lastb entry")
                timestamp = dt.datetime.fromisoformat(fields[3])
                if timestamp.tzinfo is None:
                    raise ValueError("Timestamp has no timezone")
                entries.append({"user": fields[0], "terminal": fields[1] or None,
                                "address": fields[2], "at": timestamp.isoformat()})
            except ValueError:
                malformed = True
        result.update(status="ok", entries=entries[:MAX_FAILED_LOGINS],
                      has_more=len(entries) > MAX_FAILED_LOGINS)
        if malformed or not footer_seen:
            result.update(status="partial", has_more=None,
                          error="Incomplete or unrecognized lastb output")
            self.gap("recent_failed_logins", result["error"])
        return result

    def run(self):
        if os.geteuid() != 0:
            self.gap("privileges", "Running without root: shadow, other users' processes, and logs may be inaccessible")
        for check in (self.accounts, self.persistence, self.processes, self.network, self.ssh_log):
            try:
                check()
            except (OSError, ValueError) as error:
                self.gap(check.__name__, error)
        recent_failed_logins = self.failed_logins()
        self.report["finished_at"] = utc()
        self.report["coverage"] = "partial" if self.report["gaps"] else "completed_within_scope"
        self.report["result"] = "review_required" if self.report["findings"] else "no_indicators_found"
        self.report["exit_code"] = 1 if self.report["findings"] else (2 if self.report["gaps"] else 0)
        # Keep this convenient-to-review section at the end of the JSON report.
        self.report["recent_failed_logins"] = recent_failed_logins
        return self.report


def render_text(report):
    lines = ["Linux host audit: " + clean(report["host"]), report["notice"], report["scope"], "",
             "Result: " + ("indicators require review" if report["findings"] else "no indicators found"),
             "Coverage: " + ("partial" if report["gaps"] else "completed within the stated scope"),
             "Findings: %d; limitations/gaps: %d" % (len(report["findings"]), len(report["gaps"]))]
    for item in report["findings"]:
        lines.extend(["", "[%s] %s: %s" % (item["severity"].upper(), item["code"], item["message"]),
                      "  " + clean(json.dumps(item["evidence"], ensure_ascii=False, sort_keys=True))])
    if report["gaps"]:
        lines.append("\nLimitations and gaps:")
        for gap in report["gaps"]:
            lines.append("- " + clean(gap["check"]) + ": " + clean(gap["detail"]))
    lines.append("\nCollected inventory (recent indicates a recent change, not an infection):")
    for name, entries in report["inventory"].items():
        lines.append("\n" + name + ":")
        iterable = entries if isinstance(entries, list) else [entries]
        for entry in iterable:
            lines.append(clean(json.dumps(entry, ensure_ascii=False, sort_keys=True)))
    if "recent_failed_logins" in report:
        lines.append("\nRecent failed logins (btmp, UTC):")
        lines.append(clean(json.dumps(report["recent_failed_logins"], ensure_ascii=False)))
    lines.extend(["", "Compare findings, logins, and startup entries with the expected configuration.",
                  "Exit code: %d" % report["exit_code"]])
    return "\n".join(lines) + "\n"


def write_report(path, text):
    """Create a private report; never overwrite or follow existing paths/symlinks."""
    absolute = os.path.abspath(path)
    with parent_fd(absolute) as (directory, name):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=NOTICE)
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--output", metavar="PATH", help="Create a new report file with mode 0600")
    parser.add_argument("--days", type=int, default=7, help="Days of SSH logs and recent-change markers (1-365, default: 7)")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        parser.error("Only Linux is supported")
    if not 1 <= args.days <= 365:
        parser.error("--days must be between 1 and 365")
    report = Audit(args.days).run()
    # ASCII JSON also neutralizes control characters and bidi escapes in terminals.
    output = json.dumps(report, ensure_ascii=True, indent=2) + "\n" if args.format == "json" else render_text(report)
    try:
        if args.output:
            write_report(args.output, output)
            print("Report saved: " + clean(os.path.abspath(args.output)), file=sys.stderr)
        else:
            sys.stdout.write(output)
    except (OSError, ValueError) as error:
        print("Could not write report: " + clean(error), file=sys.stderr)
        return 3
    return report["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Audit interrupted; no complete report is available", file=sys.stderr)
        sys.exit(130)

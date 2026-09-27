# Linux Host Audit

`host_audit.py` creates a local report of possible signs of compromise and settings
that warrant manual review. It requires Linux and Python 3.8 or later, with no
third-party Python libraries. It uses `ss` for network information, `journalctl`
for SSH logs, and util-linux `lastb` with `--tab-separated` support for failed
logins. Missing utilities and insufficient permissions are recorded in the report.

The script looks for indicators; it does not determine whether a host has been
compromised. The absence of findings **does not prove that the host is clean**:
malicious code may be outside the scope of the checks, and a compromised kernel,
Python interpreter, system utilities, or logs can distort the results. Warnings also
need review: for example, a package update can leave a process running with a
deleted executable.

## Usage

From the project directory:

```bash
# Print a report to the terminal; root access enables more checks.
sudo python3 -I -B host_audit.py

# Save JSON to a new file with mode 0600.
sudo python3 -I -B host_audit.py --format json --output /root/host-audit.json

# Save a text report, including SSH logs from the last 30 days.
sudo python3 -I -B host_audit.py --days 30 --output /root/host-audit.txt
```

Running without `sudo` is also supported, but coverage will be incomplete. The
`-I` option isolates Python's import paths from the current directory and
`PYTHON*` environment variables; `-B` disables bytecode generation. Existing
report files are not overwritten; choose a new name for each run. Symbolic links
in the output path are rejected. Reports contain usernames, paths, and IP
addresses, so keep access to them restricted.

## Autostart

An installer is available for systemd. Run it from the project directory:

```bash
sudo bash install-autostart.sh
```

It copies the current script and its wrapper to `/usr/local/lib/host-audit`,
sets their owner to root, and enables `host-audit.timer`. The audit runs as root
approximately two minutes after each boot. If the computer has already been
running for more than two minutes, enabling the timer starts the first audit
immediately.

Each JSON report is saved as a separate file in `/var/lib/host-audit/reports`.
The `/var/lib/host-audit/latest.json` symlink points to the most recent completed
report. Directories have mode `0700` and files have mode `0600`. Report history
is not deleted automatically. Audit exit codes `1` and `2` indicate that a report
was created with findings or gaps; systemd treats these runs as successful. If
an error or timeout occurs, the previous `latest.json` is retained, and the
incomplete file has a `.partial` suffix.

```bash
# Read the latest report.
sudo cat /var/lib/host-audit/latest.json

# Run an audit now; inspect its status and logs.
sudo systemctl start host-audit.service
systemctl status host-audit.timer host-audit.service --no-pager
journalctl -u host-audit.service -n 30 --no-pager

# Disable autostart.
sudo systemctl disable --now host-audit.timer
```

After changing the script, run the installer again to update the installed copy.
A report reflects the state at the time of the audit; programs started later
will not appear in it. The timer does not run periodic audits throughout the day.

## Checks

- Local accounts: UID 0 under a name other than `root`, and empty password fields
  in `passwd`/`shadow`. Whether login is possible also depends on PAM, SSH, and
  account status.
- Owners and permissions of important files, home directories, `.ssh`, and
  standard `authorized_keys` files. Key contents and password hashes are not
  included in the report.
- Processes: executables in `/tmp`, `/var/tmp`, `/dev/shm`, or `memfd`, and deleted
  executables. The script uses `/proc` metadata; it does not collect process
  command-line arguments or environment variables.
- Autostart: cron, local systemd configuration, SysV init, shell profiles, user
  systemd units, and XDG autostart. Files are listed with permissions,
  modification times, and SHA-256 hashes. The script flags references to temporary
  directories, downloads piped from `curl`/`wget` to a shell, and an active
  `/etc/ld.so.preload`.
- Network: listening TCP/UDP sockets and established TCP connections, with PIDs
  when permissions allow. An open port alone is not treated as a finding.
- SSH logs from systemd: failed login counts and the most recent successful
  logins. Twenty or more failures in the sample produce a warning about login
  attempts, not a conclusion that an attack succeeded. Raw log lines are not
  included in the report.
- The last 50 failed logins from `/var/log/btmp`, including local attempts:
  username, terminal, recorded address, and time in UTC. In JSON, they appear in
  the final top-level field, `recent_failed_logins`, with the newest entries
  first. The `--days` option does not limit this list; rotated btmp files are not
  read.

Example of the final JSON field:

```json
"recent_failed_logins": {
  "source": "/var/log/btmp",
  "status": "ok",
  "limit": 50,
  "entries": [
    {
      "user": "n",
      "terminal": null,
      "address": "0.0.0.0",
      "at": "2026-09-24T16:39:04+00:00"
    }
  ],
  "has_more": false
}
```

`has_more: true` means that the log contains more than 50 entries. If the log or
utility is missing, or access is denied, the result contains
`status: "unavailable"`, `entries: []`, `has_more: null`, and an explanation in
`error`; this does not mean there were no attempts. Unrecognized output is marked
as `partial`. `0.0.0.0` means that no remote address was recorded; it does not
prove where the attempt originated. Only events that the system records in btmp
are collected, which does not cover every possible authentication failure. The
script does not save markers for previous runs.

The `recent` field indicates a change within the `--days` period. A recent change
or the presence of a file alone is not a warning. SHA-256 can help compare a file
with a trusted copy obtained independently; this version does not automatically
verify files against a reference.

## Reading the results

In JSON, `findings` contains indicators for manual review: `high` indicates more
serious issues, and `warning` indicates ambiguous signs. The `gaps` field lists
limitations and skipped checks; `inventory` contains the information collected.

`result` and `coverage` are independent: findings can be present even when
coverage is incomplete. Even `completed_within_scope` refers only to the scope
described here.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings or recorded gaps within the scope of the checks; this does not guarantee a clean host |
| `1` | Findings need review; see `gaps` separately for limitations |
| `2` | No findings, but coverage is incomplete; also used for invalid CLI arguments |
| `3` | The report could not be written |
| `130` | The user interrupted the audit |

Compare unfamiliar UID 0 accounts, processes, successful SSH logins, keys, and
autostart entries with the expected configuration. For serious findings, preserve
the report and independent logs; perform further integrity checks from a trusted
system or boot medium. This script does not perform recovery.

## Scope and limits

File reads are limited to 256 KiB per file and a total budget of 16 MiB (excluding
process metadata and utility output). Traversal is limited to 2,000 objects and
a depth of 6; accounts are limited to 500 and processes to 20,000. Each external
command is limited to 15 seconds and 1 MiB of output. Reports include up to 300
sockets in each category, the last 1,000 SSH log entries, and up to 50 successful
logins within that sample. Reaching a limit is recorded as incomplete coverage.
The time limit applies to external commands; filesystem access, such as access
to an unresponsive network drive, may take longer.

Symbolic links are listed, but the script does not follow them when reading files
or traversing directories. Unchecked targets are recorded in `gaps`; ordinary
systemd symlinks can also cause these gaps. Special files are not read. The
configurations being checked are not executed. The only explicit write is the
report created with `--output`; ordinary file reads and running via `sudo` may
leave system traces, such as atime changes and audit records.

The script does not comprehensively check the filesystem, memory, firmware, all
packages, libraries, or systemd units supplied by the distribution. It does not
analyze ACLs, LDAP/NIS or other remote account sources, or SSH text logs and their
rotated archives.
It does not interpret `sshd` configuration: `Match`, `Include`,
`AuthorizedKeysCommand`, and nonstandard `AuthorizedKeysFile` settings need
separate review. In a container or with restrictions on `/proc`, only some host
information is available. The report does not replace verification against a
trusted reference or incident analysis.

Data source documentation: [kernel documentation for `/proc`](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
and [OpenSSH documentation for authorized key paths](https://man.openbsd.org/sshd_config#AuthorizedKeysFile).

## Tests

```bash
python3 -B -m unittest discover -s tests -v
```

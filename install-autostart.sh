#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
task_source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ $# -ne 0 ]]; then
    printf 'Usage: sudo bash %s\n' "$0" >&2
    exit 2
fi
if [[ $EUID -ne 0 ]]; then
    printf 'Installation requires root: sudo bash %s/install-autostart.sh\n' "$task_source_dir" >&2
    exit 1
fi

# Validate everything before installing the root-executed copies.
/usr/bin/python3 -I -B - "$task_source_dir" <<'PY'
import ast
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1])
for relative in ("host_audit.py", "autostart/run_audit.py"):
    path = source / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Invalid source file: %s" % path)
    ast.parse(path.read_text(), filename=str(path), feature_version=(3, 8))
for directory in ("/usr/local/lib/host-audit", "/etc/systemd/system", "/var/lib/host-audit"):
    path = Path(directory)
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise SystemExit("Symbolic link in installation path: %s" % component)
        if component.exists():
            metadata = component.stat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) & 0o022):
                raise SystemExit("Unsafe installation directory: %s" % component)
for path in (Path('/usr/local/lib/host-audit/host_audit.py'),
             Path('/usr/local/lib/host-audit/run_audit.py'),
             Path('/etc/systemd/system/host-audit.service'),
             Path('/etc/systemd/system/host-audit.timer')):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit("Unsafe installation path: %s" % path)
PY
/usr/bin/systemd-analyze verify "$task_source_dir/autostart/host-audit.service" "$task_source_dir/autostart/host-audit.timer"

install -d -o root -g root -m 0755 /usr/local/lib/host-audit
install -d -o root -g root -m 0700 /var/lib/host-audit
install -o root -g root -m 0644 "$task_source_dir/host_audit.py" /usr/local/lib/host-audit/host_audit.py
install -o root -g root -m 0644 "$task_source_dir/autostart/run_audit.py" /usr/local/lib/host-audit/run_audit.py
install -o root -g root -m 0644 "$task_source_dir/autostart/host-audit.service" /etc/systemd/system/host-audit.service
install -o root -g root -m 0644 "$task_source_dir/autostart/host-audit.timer" /etc/systemd/system/host-audit.timer
systemctl daemon-reload
systemctl enable --now host-audit.timer
printf 'Autostart enabled: approximately 2 minutes after boot.\nLatest report: /var/lib/host-audit/latest.json\n'

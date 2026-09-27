# Autostart Note

```bash
sudo bash /home/n/repos/host-audit/install-autostart.sh
```

The audit runs two minutes after each boot. Each JSON report is saved separately.
Read the latest report with:

```bash
sudo cat /var/lib/host-audit/latest.json
```

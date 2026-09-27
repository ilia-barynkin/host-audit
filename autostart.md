# Autostart Note

```bash
sudo bash /home/n/repos/host-audit/install-autostart.sh
```

Проверка будет запускаться через две минуты после каждой загрузки. Каждый JSON сохранится отдельно; последний можно прочитать так:

```bash
sudo cat /var/lib/host-audit/latest.json
```
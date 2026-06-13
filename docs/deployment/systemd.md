# systemd

GhostCP runs as a systemd service in production. This page shows a minimal unit
for the control-plane API; the [install script](install-script.md) will install
this automatically once built.

## API unit

`/etc/systemd/system/ghostcp-api.service`:

```ini
[Unit]
Description=GhostCP API
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=ghostcp
Group=ghostcp
EnvironmentFile=/etc/ghostcp/ghostcp.env
ExecStart=/usr/local/bin/ghostcp-api
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`EnvironmentFile` holds the variables from
[configuration](../getting-started/configuration.md) (`DATABASE_URL`,
`JWT_SECRET`, `PORT`, …).

## Managing the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ghostcp-api
sudo systemctl status ghostcp-api
journalctl -u ghostcp-api -f
```

## Managed services

The native services GhostCP configures (NGINX, PHP-FPM, BIND/PowerDNS, Postfix,
Dovecot) are their own systemd units. GhostCP renders their config and reloads
them; it does not replace their service management.

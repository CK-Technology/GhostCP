# Deployment

GhostCP is a **host-level control panel**. Production deployment means installing
it onto a server and managing it with **systemd** — the HestiaCP model,
modernized. It is **not** a container-orchestration target; the `docker/` stack is
for [development](../development/docker.md) only.

- [Requirements](requirements.md) — supported OS, hardware, prerequisites
- [Install Script](install-script.md) — the planned `install.sh` design
- [systemd](systemd.md) — running the services as units
- [Reverse Proxy](reverse-proxy.md) — TLS termination in front of the API
- [Tailscale](tailscale.md) — private management plane (admin panel + SSH)
- [Proxmox VE Firewall](proxmox-firewall.md) — PVE firewall for a GhostCP VM
- [Distributed](distributed.md) — Dev ↔ Prod topology and shared central services

> The production installer is **designed here but not yet built**. For now,
> deploy by building from source and wiring systemd units manually, following
> these pages.

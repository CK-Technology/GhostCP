# Proxmox VE Firewall (VM install)

A common GhostCP deployment is a dedicated **VM on Proxmox VE**. Proxmox has its
own firewall layered in front of the guest, so you configure access in two
places: the **PVE firewall** (host side) and the guest's own firewall. This page
covers the PVE side for a GhostCP VM.

> The PVE firewall is **off by default** at the datacenter level. Nothing is
> filtered until you enable it. Enable deliberately and confirm you still have
> console/SSH access before disconnecting.

## Firewall levels

PVE applies rules at three scopes, most-general first:

| Level | Scope | Where |
|-------|-------|-------|
| **Datacenter** | all nodes/guests | Datacenter → Firewall |
| **Node** | one host | Node → Firewall |
| **VM/CT** | one guest | VM → Firewall |

A packet to the GhostCP VM must pass the datacenter, node, **and** VM rules. The
VM-level tab is where you allow GhostCP's service ports.

## Enable, safely

1. **Datacenter → Firewall → Options:** keep the default inbound policy `DROP`,
   outbound `ACCEPT`. Add an SSH allow rule **before** turning the firewall
   `On`, so you don't lock yourself out.
2. **Node → Firewall:** ensure management access (SSH 22, PVE UI 8006) is
   permitted to the host.
3. **VM → Firewall → Options:** set the VM firewall `On`. By default this also
   requires per-VM rules; absent any allow rule, inbound is dropped.

## Ports for a GhostCP VM

Open only what the host actually serves. Map these to the
[requirements](requirements.md) port list:

| Service | Port(s) | Proto | Needed when |
|---------|---------|-------|-------------|
| HTTP | 80 | TCP | web hosting + ACME HTTP-01 |
| HTTPS | 443 | TCP | web hosting, panel reverse proxy |
| DNS | 53 | TCP+UDP | serving authoritative DNS |
| SMTP | 25 | TCP | inbound mail |
| Submission | 587, 465 | TCP | outbound/client mail |
| IMAP(S) | 143, 993 | TCP | mailbox access |
| SSH (mgmt) | 22 | TCP | administration (restrict source) |

Do **not** expose the control-plane API port (default 8080) directly — front it
with the [reverse proxy](reverse-proxy.md) on 443 and keep 8080 bound to
localhost inside the VM.

## Using a Security Group

Rather than repeating rules per VM, define a reusable **Security Group** at the
datacenter level and attach it to each GhostCP VM.

1. **Datacenter → Firewall → Security Group → Create**, name it e.g.
   `ghostcp`.
2. Add inbound `ACCEPT` rules for the ports above.
3. **VM → Firewall → Add → Security Group** and select `ghostcp`.

Example rule set for the group (conceptually):

```
IN  ACCEPT  -p tcp     --dport 80
IN  ACCEPT  -p tcp     --dport 443
IN  ACCEPT  -p tcp/udp --dport 53
IN  ACCEPT  -p tcp     --dport 25
IN  ACCEPT  -p tcp     --dport 587
IN  ACCEPT  -p tcp     --dport 465
IN  ACCEPT  -p tcp     --dport 143
IN  ACCEPT  -p tcp     --dport 993
IN  ACCEPT  -p tcp     --dport 22   -source <your-admin-CIDR>
```

Restrict SSH (and ideally the panel) to a trusted admin CIDR with an **IPSet**
(Datacenter → Firewall → IPSet) instead of leaving 22 open to the world.

## DNS secondaries

If this VM is a primary nameserver transferring zones to external secondaries,
ensure **outbound** 53 is allowed (it is, under the default `ACCEPT` outbound
policy) and that inbound 53 is open for the secondaries' queries/transfers. Zone
transfers are authenticated with TSIG — see
[authoritative interop](../dns/authoritative-interop.md).

## Verify

From outside the VM:

```bash
# web reachable
curl -I http://<vm-ip>/

# DNS answering (if serving DNS)
dig @<vm-ip> example.com SOA
```

From the host, confirm the firewall is active and rules are applied:

```bash
pve-firewall status
pve-firewall compile     # show the compiled ruleset
```

## Guest firewall

The PVE firewall complements, but does not replace, hardening inside the guest.
Apply host-level firewalling (UFW/nftables) and the rest of the
[hardening](../security/hardening.md) guidance within the VM as well.

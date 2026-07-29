# Public ingress notes — `sentinel.bhm.li`

Date: 2026-07-28

This is a **commissioning beta ingress only**. It is not a production ingress.

## What it is

- A Cloudflare tunnel terminates TLS for the public hostname `sentinel.bhm.li` and forwards plain HTTP to the local Zabbix web at `10.10.97.18:18080`.
- The Cloudflare connector runs on the same host as the Compose project. The web container publishes directly to the LAN address `10.10.97.18:18080` so the tunnel always has a deterministic non-loopback target.
- The Zabbix `Admin` account password was changed by the user before this URL was reachable. No agent or operator has recorded that password.

## What is not in scope

- Rate limiting, fail2ban, or MFA on the Zabbix front end.
- A real production Zabbix ingress with firewall, egress control, image provenance, identity-bound approval, and durable encrypted backup.
- Sentinel's `apply` step, OpenBao bootstrap, StackStorm, monitoring apply, and any monitoring target registration.
- The current synthetic-only PostgreSQL volume is the only persistence; it is intentionally not backed up.

## Operator responsibilities

- Keep the Zabbix `Admin` account password strong, unique to this beta, and not used anywhere else.
- Treat any Zabbix configuration changes through `sentinel.bhm.li` as disposable.
- Do not register real hosts or real credentials.
- Do not enable notifications, remediation, StackStorm, or OpenBao from this ingress.

## Local loopback remains the source of truth

- `http://10.10.97.18:18080/` is the address the tunnel targets and the same address the operator can use from another host on the LAN.
- The public URL is convenient for the operator; the LAN address is what Sentinel validates.
- If the Cloudflare connector is down, the LAN address is still up.

## Acceptance

- Synthetic-only.
- No real infrastructure, no real credentials, no monitoring apply, no encrypted backup, no OpenBao, no StackStorm, no production acceptance.

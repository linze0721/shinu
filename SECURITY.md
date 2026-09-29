# Security Policy

Use this policy to report suspected vulnerabilities in shinu.

## Supported versions

Shinu is pre-1.0. There are no released versions yet; the workspace version is `0.1.0`. Only the `main` branch receives fixes.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/linze0721/shinu/security/advisories/new). Please do not open a public issue for a vulnerability. No response-time SLA is promised; maintainers will acknowledge reports on a best-effort basis.

## Scope

The following security boundaries are in scope:

- Multi-tenant project isolation, including cross-project access and disclosure of whether another project's spaces or commits exist.
- Bearer-token and console-session authentication, including token handling in [`crates/shinu-crypto`](crates/shinu-crypto).
- Escape from the Firecracker Jailer/microVM sandbox. Guest code is untrusted by design; escaping the jailer sandbox is in scope.
- Per-project quota enforcement and API rate-limit bypass.
- Guest-to-host and guest egress controls, including `SHINU_NET_ALLOW`, `SHINU_HOST_ALLOW`, and iptables exception ordering.
- The `shinud` HTTP surface, including authentication and request routing.

## Deployment responsibilities and boundaries

- `shinud` implements no TLS. It MUST remain bound to loopback and sit behind a TLS-terminating proxy; the repository provides a [Caddy configuration](packaging/caddy/Caddyfile). The daemon's default bind address is `127.0.0.1:7878`. Exposing its cleartext listener is an operator deployment failure.
- `shinud` runs as root by design to configure host resources.
- `SHINU_ADMIN_TOKEN` gates the project-limits administration endpoint and fails closed when unset.
- Guest code is expected to be untrusted. A guest escape from the Jailer sandbox remains in scope, as stated above.

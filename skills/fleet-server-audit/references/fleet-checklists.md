# Fleet Server Audit Checklist

Use this reference for multi-host work. Do not paste it wholesale; use it to keep coverage complete.

## Inventory coverage

- Every host has a stable name.
- SSH user and port are explicit or inherited from a documented default.
- Tags include environment (`prod`, `staging`, `dev`) and role hints when known.
- Criticality is known for production systems.
- Hosts that require bastion/proxy access are marked separately.
- Unreachable hosts are kept in the report rather than silently dropped.

## Classification evidence

Classify from evidence:

- Docker host: `docker version`, `docker ps`, containerd/dockerd services.
- Web gateway: public 80/443, nginx/apache/caddy, reverse proxy configs.
- Stateful: database/queue/cache processes, data volumes, persistent mounts.
- Browser/crawler: Chrome, browserless, Playwright, Puppeteer, Selenium, Xvfb.
- Dev/CI: build tools, CI agents, many checkouts, frequent Docker builds.
- Monitoring: Prometheus/Grafana/Loki/exporters/cloud monitoring agents.

## Fleet-level patterns

Look for:

- Same risky config across many hosts.
- One role class lacking memory limits.
- One network port exposed fleet-wide.
- Missing fail2ban on SSH-exposed hosts.
- Inconsistent swap strategy.
- Missing telemetry on hosts with prior crashes.
- State data without backup evidence.
- Containers that run privileged or mount Docker socket.

## Rollout safety

- Start with one non-critical representative host.
- Separate stateless from stateful.
- Use a canary batch before fleet-wide application.
- Keep rollback commands next to every proposed change.
- Verify after each batch.
- Do not combine SSH hardening, firewall changes, and service restarts in the same rollout step.

## Recommended report artifacts

- `summary.md`: human-readable executive report.
- `summary.json`: machine-readable risk data.
- `hosts/<name>/raw_audit.txt`: raw per-host evidence.
- `hosts/<name>/stderr.txt`: SSH/errors.
- `hosts/<name>/summary.json`: parsed host summary.


# Risk Matrix

Use this matrix to classify findings.

## Priority levels

P0 Immediate:

- Active compromise indicators.
- Public unauthenticated admin/data service.
- Disk or inode usage likely to stop writes soon.
- Repeated crash or reboot with unresolved cause.
- SSH/firewall change could lock out all access.
- Backup absent before a destructive or stateful operation.

P1 High:

- No memory limits on containers that can spike or leak.
- Password SSH exposed with brute-force noise.
- No fail2ban/rate limiting on public SSH.
- Stateful service has no backup/restore path.
- Sensitive secret file is world-readable.
- Docker socket exposed to a container without strong justification.

P2 Medium:

- Missing health checks.
- No historical telemetry for resource incidents.
- Logs too noisy or retention too short.
- Overbroad public bind addresses but protected by another layer.
- Outdated packages without known active exploitation in context.

P3 Low:

- Documentation gaps.
- Cleanups that reduce clutter but do not materially change risk.
- Dashboard improvements.
- Nice-to-have service metadata.

## Recommendation quality

Every actionable recommendation should have:

- Evidence
- Impact
- Exact change
- Blast radius
- Rollback
- Verification command

Avoid recommendations like "harden SSH" or "optimize Docker" without concrete commands, risks, and checks.


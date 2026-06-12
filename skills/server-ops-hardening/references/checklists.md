# Server Operations and Security Checklist

Use this checklist for full audits. Do not dump it verbatim into the final answer; use it to make sure the report is complete.

## Linux baseline

- OS and kernel are supported.
- Time sync is active.
- Disk has enough free space and inode headroom.
- Journald or syslog persists enough history to explain crashes.
- `sysstat`, cloud monitoring, or node exporter exists for historical CPU/RAM/disk data.
- Swap exists when workloads are bursty; swappiness is intentional.
- Failed systemd units are understood.
- Cron jobs and timers are known.

## Stability

- Recent reboots have a clear shutdown or crash explanation.
- Previous boot logs have been checked for OOM, memory pressure, kernel panic, disk errors, thermal issues, and service failures.
- Heavy jobs are scheduled with concurrency limits.
- Stateless services have restart policies and health checks.
- Stateful services have conservative memory limits and backup/restore validation before any restart automation.

## Docker and container hosts

- Every risky container has `mem_limit` or equivalent runtime memory limit.
- Containers have PID limits when appropriate.
- Browser automation containers have separate limits because Chrome can spike.
- Docker socket is not mounted into untrusted containers.
- Privileged, host network, host PID, and broad host filesystem mounts are justified.
- Public ports are intentional and documented.
- Compose files are the source of truth; manual `docker run` containers are documented or migrated.
- Images are pinned or update policy is understood.
- Docker log growth is controlled.

## SSH and accounts

- SSH key auth works before disabling password auth.
- Root login policy matches operations model.
- `AllowUsers` or equivalent is considered on public machines.
- Fail2ban or equivalent protects password-exposed SSH.
- Unknown users, UID 0 users, and stale accounts are reviewed.
- Sudoers changes are backed up and validated with `visudo`.

## Firewall and exposure

- `ss -tulpn` public binds are reviewed.
- Admin panels, databases, Redis, Docker API, Prometheus, Grafana, and internal APIs are not publicly exposed unless intentionally protected.
- Host firewall and cloud security groups are both considered. A host firewall alone may not explain cloud exposure, and a cloud security group alone may not protect localhost-bound mistakes on shared networks.
- Reverse proxy configs map to expected upstreams.

## Updates and packages

- Security updates are installed or scheduled.
- Unattended upgrades are configured where appropriate.
- EOL distributions are flagged.
- Critical packages like OpenSSH, Docker, nginx/apache/caddy, OpenSSL, and language runtimes are checked.

## Secrets

- Do not print secret values in reports.
- Report risky paths and variable names only.
- Check shell history, `.env`, compose files, app configs, world-readable keys, and backup archives.
- Ensure private keys are `0600` and not group/world-readable.

## Backups and recovery

- Identify stateful data: databases, Docker volumes, bind-mounted app data, object storage, config dirs, SSL certs.
- Backups are off-host or at least outside the failure domain.
- Restore has been tested or the lack of restore proof is called out.
- Before disruptive changes, note snapshot/backup status.

## Monitoring

- Alerts exist for memory, disk, CPU load, service health, certificate expiration, and backup failure.
- Logs preserve enough data for post-incident root cause.
- For memory incidents, record top processes and container stats before acting.


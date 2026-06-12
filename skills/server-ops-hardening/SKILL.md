---
name: server-ops-hardening
description: Use this skill whenever the user asks to inspect, optimize, stabilize, harden, secure, or troubleshoot a Linux server, VPS, cloud host, Docker host, reverse proxy host, SSH-accessed machine, or production machine. Trigger for prompts like "服务器崩了/无法访问/很慢", "优化服务器", "加固服务器安全", "检查每台机器配置", "Docker 内存限制", "SSH 安全", "fail2ban/firewall", "服务器体检", or "给这台机器做运行优化和安全方案". This skill performs evidence-first diagnostics, machine-specific performance tuning, Docker/systemd/resource guardrails, network/SSH exposure review, backup/rollback planning, and security hardening recommendations. Use it even if the user only asks a short operational question, because server changes are high-impact and should be audited before modification.
---

# Server Ops Hardening

Use this skill to turn a vague server concern into a careful, evidence-backed operations and security workflow. The goal is not to apply a generic checklist. The goal is to identify what this machine is, what it runs, what can break, what is exposed, and which changes reduce risk without surprising the user.

For multi-host inventory, comparison, risk scoring, and staged rollout planning, use `fleet-server-audit` first. Return to this skill for any single host that needs deeper diagnosis, config edits, or post-change verification.

## Operating principles

- Start read-only. Gather facts before changing anything.
- For fleets, avoid one-size-fits-all tuning. Use `fleet-server-audit` to classify hosts, then apply this skill host-by-host.
- Separate cause, risk, and remediation. A server can be slow because of SSH transport, IDE/bootstrap, CPU, memory pressure, disk I/O, DNS, network filtering, or application startup.
- Treat security hardening as change management. SSH, firewall, Docker networking, automatic updates, and service restarts can lock the user out or break production.
- Prefer least-disruptive fixes first: container limits, service health checks, log retention, swap tuning, rate limits, and monitoring before broad platform rewrites.
- Make every recommendation machine-specific. Tie it to CPU/RAM/disk/swap, running services, container list, exposed ports, auth posture, cloud/firewall context, and workload role.
- Verify after every change. Show concrete evidence such as `docker inspect`, `docker stats`, `systemctl status`, `ss -tulpn`, `curl`, `journalctl`, or application health checks.
- Preserve rollback. Before editing service files, firewall rules, compose files, nginx configs, SSH configs, or sysctl files, copy or note the original state and explain how to undo.

## Safety model

Default mode is audit-only. Do not modify the server unless the user clearly asks to fix/apply/harden/enable/restart/change or confirms a proposed change.

High-risk changes require an explicit warning and a rollback path:

- SSH port, `PasswordAuthentication`, `PermitRootLogin`, `AllowUsers`, authorized keys, PAM, or sudoers changes
- Firewall default-deny, security group assumptions, fail2ban bans, iptables/nftables rules
- Stopping/removing containers, pruning Docker, deleting logs, rotating databases
- Rebooting, kernel/sysctl changes that affect networking, filesystem mounts, disk partitioning
- Database memory limits, database restarts, queue restarts, or stateful container limits
- Certbot/nginx/apache routing changes on production endpoints

If the user asks for “仅回答” or only wants diagnosis, do not implement. Give the shortest evidence-backed conclusion.

## Fast triage workflow

When the server is currently down, slow, recently rebooted, unreachable, or suspected crashed:

1. Establish timeline.
   - `uptime -s`
   - `who -b`
   - `last -x -F reboot shutdown crash -n 12`
   - `journalctl --list-boots --no-pager`
2. Check previous boot evidence.
   - `journalctl -b -1 -n 200 --no-pager`
   - `journalctl -b -1 -p warning..emerg --no-pager`
   - Search for `oom`, `out of memory`, `killed process`, `memory pressure`, `panic`, `watchdog`, `soft lockup`, `hard lockup`, `i/o error`, `ext4`, `nvme`, `read-only`, `thermal`, `segfault`.
3. Check current health.
   - `free -h`, `swapon --show`, `df -h`, `uptime`
   - `systemctl --failed --no-pager`
   - `ss -tulpn`
   - `docker ps`, `docker stats --no-stream` if Docker exists
4. Distinguish server outage from access path issues.
   - SSH auth/transport: `journalctl -u ssh --since ...`
   - IDE/remote bootstrap: compare auth success, port-ready, extension install, and app startup timestamps.
   - Network/service endpoint: test localhost first, then public endpoint if available.
5. Report conclusion with confidence.
   - Confirmed cause: direct log evidence.
   - Probable cause: strong resource/timeline evidence but missing exact killing process.
   - Unknown: state what evidence is absent and what instrumentation should be added.

## Full audit workflow

Use this workflow for “optimize”, “harden”, “check this machine”, “create a plan for every server”, or “make it stable and secure”.

### 1. Inventory

Identify the server profile:

- OS/kernel/virtualization/cloud hints: `hostnamectl`, `uname -a`, `lsb_release -a` or `/etc/os-release`, `systemd-detect-virt`
- Hardware/resources: `nproc`, `lscpu`, `free -h`, `swapon --show`, `lsblk`, `df -h`, `findmnt`
- Workload role: web app, Docker host, database, crawler/browser automation, CI runner, monitoring node, storage node, development box
- Runtime managers: Docker/Compose, systemd services, cron/timers, nginx/apache/caddy, database services, language runtimes
- Exposure: listening ports, public bind addresses, reverse proxy config, cloud metadata/firewall clues if available

Prefer the bundled read-only script:

```bash
/root/.agents/skills/server-ops-hardening/scripts/server_audit.sh
```

If running on another machine, copy the script there or recreate it from this skill's `scripts/server_audit.sh`.

### 2. Resource and stability analysis

Check:

- RAM, swap size, `vm.swappiness`, OOM evidence, `systemd-journald` memory pressure messages
- CPU load and steal, run queue, top CPU processes, scheduler pressure
- Disk usage, inode usage, journal size, Docker disk usage, high-churn logs
- Disk errors and filesystem issues
- Docker container memory/PID limits, restart policies, health checks, logs, bind mounts
- Cron/systemd timers that launch heavy jobs
- sysstat/atop availability for historical analysis

Common recommendations:

- Add per-container `mem_limit`, `memswap_limit`, and `pids_limit` for non-stateful containers.
- Keep total container hard limits below physical RAM so host services retain breathing room.
- Set gentle swap behavior such as `vm.swappiness=10` when swap exists and the host suffered memory pressure.
- Add health checks and restart policies for stateless services.
- Add monitoring or a memory-pressure guard only after explaining what it will restart and why.
- Install or enable historical telemetry (`sysstat`, cloud monitoring, node exporter, journald retention) if root cause evidence was missing.

### 3. Security posture review

Cover at minimum:

- SSH:
  - root login, password auth, key auth, authorized keys, unusual users, `AllowUsers`/`DenyUsers`
  - brute-force evidence, fail2ban status, SSH port exposure
- Accounts and privilege:
  - sudoers, UID 0 users, inactive accounts, shell access, password aging where relevant
- Firewall and exposed services:
  - `ss -tulpn`, ufw/firewalld/nftables/iptables, cloud security group caveat
  - public bind addresses for admin panels, databases, Redis, Docker API, Prometheus, dashboards
- Updates:
  - pending security updates, unattended upgrades, kernel livepatch availability where applicable
- Secrets:
  - `.env`, compose files, shell history, app configs, mounted secrets, world-readable key files
  - Do not print secret values. Report file paths and variable names only.
- Docker security:
  - privileged containers, Docker socket mounts, host network/PID/IPC, writable host mounts, root containers, no-new-privileges, capabilities, exposed ports
- Logging and detection:
  - journald persistence/retention, fail2ban, auth logs, auditd if appropriate, cloud agent health
- Backups:
  - data directories, database dumps, volume backups, off-host backup, restore test evidence

When security issues are code-level rather than host-level, recommend pairing with `$codex-security:security-scan` for repository security scanning.

### 4. Optimization and hardening plan

Group findings by priority:

- P0 Immediate risk: likely outage recurrence, public unauthenticated admin/data service, disk nearly full, active compromise evidence, SSH lockout hazard.
- P1 High: no container limits on memory-risk workloads, password SSH exposed with brute-force activity, no backups for stateful services, no log retention, no update plan.
- P2 Medium: tuning improvements, missing health checks, noisy logs, overbroad binds, no historical telemetry.
- P3 Nice-to-have: cleanup, documentation, dashboards, long-term architecture.

For each finding include:

- Evidence: command output summary, file path, service/container name, timestamp if relevant
- Impact: what can fail or be exploited
- Recommendation: exact change
- Risk: what could break
- Rollback: how to undo
- Verification: what command proves it worked

### 5. Implementation rules

When authorized to apply fixes:

1. Apply the smallest useful change.
2. For config files, create a timestamped backup when practical.
3. Use established package/service managers instead of ad hoc daemons.
4. Avoid destructive cleanup unless the user explicitly approves.
5. Restart only affected services when possible.
6. Verify function from localhost and, if available, from public endpoint.
7. Re-check resource/security posture after changes.

For Docker Compose:

- Prefer editing the compose source file, then `docker-compose config`, then `docker-compose up -d`.
- If old `docker-compose 1.29.2` fails with `KeyError: 'ContainerConfig'`, explain the compatibility issue. If data is in bind mounts or named volumes and deletion is safe, remove the stopped old container and run `docker-compose up -d` again.
- Verify with:

```bash
docker inspect <containers> --format '{{.Name}} Memory={{.HostConfig.Memory}} Swap={{.HostConfig.MemorySwap}} Pids={{.HostConfig.PidsLimit}} Restart={{.HostConfig.RestartPolicy.Name}}'
docker stats --no-stream
docker ps
```

For memory pressure guardrails:

- Use container memory limits before adding automatic restarters.
- Only add a watchdog that restarts services if the workload is restart-safe or the user approves.
- State the thresholds and container selection logic plainly.
- Log before acting so the next incident has evidence.

## Output formats

For a short diagnosis request:

```markdown
原因：[confirmed/probable/unknown] ...
证据：...
下一步：...
```

For a full audit:

```markdown
**Executive Summary**
- Overall risk:
- Likely failure modes:
- Biggest security risks:
- Recommended first changes:

**Machine Profile**
- OS/kernel:
- CPU/RAM/swap/disk:
- Workload:
- Public exposure:

**Findings**
| Priority | Area | Evidence | Impact | Recommendation | Verification |

**Implementation Plan**
1. ...

**Rollback Plan**
- ...

**Commands Used**
- ...
```

For an applied fix:

```markdown
**Changed**
- ...

**Verified**
- ...

**Residual Risk**
- ...

**Watch Next**
- ...
```

## Bundled resources

- `scripts/server_audit.sh`: read-only evidence collection for Linux/Docker hosts.
- `references/checklists.md`: detailed checklist for Linux, Docker, SSH, firewall, logging, backups, and monitoring.
- `references/risk-matrix.md`: priority and risk scoring guidance.

Read the reference files only when the task needs a full audit, security hardening plan, or implementation checklist. For quick incident diagnosis, the fast triage workflow is usually enough.

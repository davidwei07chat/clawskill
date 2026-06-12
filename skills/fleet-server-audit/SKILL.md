---
name: fleet-server-audit
description: Use this skill whenever the user wants to audit, compare, optimize, harden, monitor, or generate security and operations recommendations for multiple Linux servers, VPS machines, Docker hosts, SSH hosts, crawler hosts, production nodes, or a fleet of machines. Trigger for prompts like "检查 20 台服务器", "批量服务器体检", "每台机器自动识别配置", "多服务器加固方案", "fleet audit", "server inventory", "批量 SSH 检查", or "把服务器优化策略复制到多台机器". This skill coordinates multi-host read-only collection, per-machine classification, risk scoring, summary reports, and safe rollout planning. Pair with server-ops-hardening for deep single-host diagnosis and remediation.
---

# Fleet Server Audit

Use this skill when the user's real problem spans more than one machine. Its job is to orchestrate repeatable, read-only evidence collection across a fleet, classify hosts by role and risk, and produce a prioritized rollout plan. It deliberately avoids changing remote machines by default.

For single-machine incident triage or direct remediation, use `server-ops-hardening`. For fleet-scale inventory, comparison, risk scoring, and rollout planning, use this skill first, then delegate suspicious or high-risk hosts to `server-ops-hardening`.

## Safety model

- Default to read-only SSH collection.
- Never push SSH/firewall/sysctl/Docker changes to every host without an explicit plan and user approval.
- Treat unknown host roles as high-change-risk. A database host, queue host, or stateful storage node should not receive generic container restart or memory limit automation.
- Keep raw evidence per host so later recommendations are auditable.
- Use timeouts and per-host failure reporting; one bad host should not block the fleet summary.
- Do not print secrets from remote hosts. If secret-like files or env vars are found, report paths and variable names only.

## Workflow

### 1. Clarify fleet scope

Determine:

- Inventory source: file path, pasted list, cloud export, SSH config, or manually named hosts
- Access method: SSH user, key, port, bastion/proxy, sudo availability
- Fleet intent: audit-only, risk report, optimization plan, security hardening plan, or apply approved changes later
- Host types that must be treated carefully: databases, queues, payment/order systems, stateful storage, Kubernetes control planes
- Output location and desired format: Markdown, JSON, CSV, per-host evidence bundles

If the user did not provide an inventory, ask for one or propose the supported inventory formats below.

### 2. Collect read-only evidence

Prefer the bundled script:

```bash
python3 /root/.agents/skills/fleet-server-audit/scripts/fleet_audit.py \
  --inventory /path/to/hosts.csv \
  --audit-script /root/.agents/skills/server-ops-hardening/scripts/server_audit.sh \
  --out /tmp/fleet-audit-$(date +%Y%m%d-%H%M%S)
```

The script:

- Reads JSON, CSV, or simple line-based inventory.
- Connects with SSH in batch mode.
- Streams the single-host read-only audit script to each remote host.
- Saves raw logs under `hosts/<host>/raw_audit.txt`.
- Writes `summary.json` and `summary.md`.
- Flags unreachable hosts separately from risky hosts.

Do not assume the script is the only valid method. If SSH is unavailable, ask the user to run the single-host `server_audit.sh` on each machine and collect outputs, then summarize those outputs.

### 3. Classify hosts

Classify by evidence, not names alone:

- Docker host: Docker exists and has running containers.
- Web gateway: nginx/apache/caddy or public HTTP/HTTPS listeners.
- Database/stateful: postgres/mysql/mariadb/mongodb/redis/elasticsearch/rabbitmq/kafka or data volumes.
- Browser/crawler: browserless/chrome/playwright/puppeteer/selenium/Xvfb.
- Dev/CI: many language runtimes, build tools, git checkouts, CI agents, Docker build activity.
- Monitoring/logging: prometheus/grafana/loki/agent/exporter.
- Unknown: insufficient evidence or unreachable.

### 4. Score risk

Use the risk matrix:

- P0: likely outage recurrence, public unauthenticated sensitive service, disk nearly full, active compromise evidence, unreachable critical host.
- P1: no memory limits on bursty containers, password SSH exposed with brute-force evidence, no backups for stateful hosts, Docker socket/privileged container risks.
- P2: missing health checks, weak telemetry, overbroad binds protected by another layer, outdated packages.
- P3: documentation, cleanup, dashboard improvements.

Fleet-level risk is not just the average. One P0 database host can dominate the plan.

### 5. Generate recommendations

Produce:

- Fleet executive summary
- Host inventory table
- Per-host role and risk
- Common patterns across the fleet
- Host-specific recommendations
- Safe rollout sequence
- Rollback and verification plan
- Items that need human confirmation before changes

Separate recommendations into:

- Universal safe defaults: logging, telemetry, backup verification, non-invasive documentation
- Role-specific defaults: Docker limits, browser container limits, web gateway headers/TLS, Redis bind/auth, database backup/restore
- High-risk gated changes: SSH/fail2ban/firewall, database restarts, Docker socket removal, public port closure

### 6. Rollout planning

When the user wants to apply changes:

1. Start with one low-risk representative host.
2. Snapshot relevant config or record rollback commands.
3. Apply the smallest useful change.
4. Verify the host.
5. Wait for user confirmation before scaling to the next batch.
6. Roll out by host class, not all at once.

Suggested rollout order:

- Observability/logging first.
- Container limits for stateless and crawler/browser hosts second.
- Web gateway exposure hardening third.
- SSH/firewall hardening only after confirming alternate access and current keys.
- Stateful database/queue/storage changes last and only with backup/restore evidence.

## Inventory formats

CSV:

```csv
name,host,user,port,tags,role
prod-web-1,203.0.113.10,root,22,prod;web,web
crawler-1,203.0.113.11,ubuntu,22,prod;crawler,crawler
```

JSON:

```json
[
  {"name": "prod-web-1", "host": "203.0.113.10", "user": "root", "port": 22, "tags": ["prod", "web"]},
  {"name": "crawler-1", "host": "203.0.113.11", "user": "ubuntu", "port": 22, "tags": ["prod", "crawler"]}
]
```

Plain text:

```text
prod-web-1=root@203.0.113.10:22 prod web
crawler-1=ubuntu@203.0.113.11 crawler
203.0.113.12
```

## Report structure

Use this structure for final reports:

```markdown
**Fleet Summary**
- Hosts checked:
- Unreachable:
- P0/P1 count:
- Common risks:
- First recommended rollout:

**Host Matrix**
| Host | Reachable | Role | RAM | Docker | Public Exposure | Top Risk | Next Action |

**Common Patterns**
- ...

**Per-Host Recommendations**
### host-name
- Evidence:
- Risk:
- Recommendation:
- Rollback:
- Verification:

**Rollout Plan**
1. ...

**Needs Human Confirmation**
- ...
```

## Bundled resources

- `scripts/fleet_audit.py`: batch SSH collection and summary generator.
- `references/fleet-checklists.md`: host classification, rollout, and evidence checklist.
- `evals/evals.json`: test prompts for this skill.

Use `server-ops-hardening` for the single-host script and deep remediation workflow.

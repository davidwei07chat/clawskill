#!/usr/bin/env python3
"""Batch read-only server audit over SSH.

This script intentionally uses only the Python standard library. It does not
modify remote hosts; it streams a read-only audit shell script through SSH,
saves raw output, and writes lightweight Markdown/JSON summaries.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class Host:
    name: str
    host: str
    user: str = ""
    port: int = 22
    tags: list[str] | None = None
    role: str = ""

    @property
    def ssh_target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host


def parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in re.split(r"[;, ]+", str(value)) if x.strip()]


def parse_plain_line(line: str, default_user: str, default_port: int) -> Host:
    tokens = line.split()
    target = tokens[0]
    tags = tokens[1:]
    name = ""
    if "=" in target:
        name, target = target.split("=", 1)
    user = default_user
    port = default_port
    if "@" in target:
        user, target = target.split("@", 1)
    if ":" in target and not target.startswith("["):
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            target = host_part
            port = int(port_part)
    host = target.strip("[]")
    return Host(name=name or host, host=host, user=user, port=port, tags=tags)


def load_inventory(path: Path, default_user: str, default_port: int) -> list[Host]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        hosts = []
        for item in data:
            host = str(item["host"])
            hosts.append(
                Host(
                    name=str(item.get("name") or host),
                    host=host,
                    user=str(item.get("user") or default_user),
                    port=int(item.get("port") or default_port),
                    tags=parse_tags(item.get("tags")),
                    role=str(item.get("role") or ""),
                )
            )
        return hosts
    if path.suffix.lower() == ".csv":
        hosts = []
        for row in csv.DictReader(text.splitlines()):
            host = str(row["host"]).strip()
            hosts.append(
                Host(
                    name=(row.get("name") or host).strip(),
                    host=host,
                    user=(row.get("user") or default_user).strip(),
                    port=int(row.get("port") or default_port),
                    tags=parse_tags(row.get("tags")),
                    role=(row.get("role") or "").strip(),
                )
            )
        return hosts
    hosts = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        hosts.append(parse_plain_line(line, default_user, default_port))
    return hosts


def run_host(host: Host, audit_script: str, timeout: int) -> tuple[int, str, str, float]:
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={min(timeout, 30)}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        str(host.port),
        host.ssh_target,
        "bash -s",
    ]
    started = time.time()
    try:
        result = subprocess.run(
            cmd,
            input=audit_script,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr, time.time() - started
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr + f"\nTimeout after {timeout}s", time.time() - started


def find_section(text: str, name: str) -> str:
    marker = f"===== {name} ====="
    start = text.find(marker)
    if start < 0:
        return ""
    next_marker = text.find("\n===== ", start + len(marker))
    return text[start: next_marker if next_marker >= 0 else len(text)]


def regex_first(pattern: str, text: str, default: str = "") -> str:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else default


def infer_roles(text: str, declared_role: str) -> list[str]:
    roles = set(parse_tags(declared_role))
    lowered = text.lower()
    if "docker ps" in lowered or "docker version" in lowered:
        roles.add("docker")
    if re.search(r"\b(nginx|apache2|httpd|caddy)\b", lowered):
        roles.add("web")
    if re.search(r"\b(postgres|postgresql|mysql|mariadb|mongodb|redis|elasticsearch|rabbitmq|kafka)\b", lowered):
        roles.add("stateful")
    if re.search(r"\b(browserless|chrome|chromium|playwright|puppeteer|selenium|xvfb)\b", lowered):
        roles.add("crawler-browser")
    if re.search(r"\b(prometheus|grafana|loki|node_exporter|exporter)\b", lowered):
        roles.add("monitoring")
    return sorted(roles) or ["unknown"]


def analyze(host: Host, rc: int, stdout: str, stderr: str, duration: float) -> dict[str, Any]:
    text = stdout + "\n" + stderr
    mem_line = regex_first(r"^Mem:\s+(.+)$", text)
    swap_line = regex_first(r"^Swap:\s+(.+)$", text)
    swappiness = regex_first(r"vm\.swappiness\s*=\s*(\d+)", text)
    disk_worst = ""
    disk_pcts = [int(x) for x in re.findall(r"\s(\d+)%\s+/", text)]
    if disk_pcts:
        disk_worst = f"{max(disk_pcts)}%"
    public_ports = []
    for line in find_section(text, "network exposure").splitlines():
        if "LISTEN" in line and ("0.0.0.0:" in line or "[::]:" in line):
            public_ports.append(line.strip())
    unlimited_containers = []
    for line in find_section(text, "docker").splitlines():
        if " Memory=0 " in f" {line} " or "Memory=0 " in line:
            name = line.split()[0] if line.split() else "unknown"
            unlimited_containers.append(name)
    has_oom_evidence = bool(re.search(r"oom|out of memory|killed process|memory pressure", text, re.I))
    ssh_password = regex_first(r"^passwordauthentication\s+(\S+)", text.lower())
    root_login = regex_first(r"^permitrootlogin\s+(\S+)", text.lower())
    fail2ban = "fail2ban-client" in text.lower() and "not found" not in text.lower()
    roles = infer_roles(text, host.role)
    risks = []
    if rc != 0:
        risks.append(("P0", "Host unreachable or audit failed"))
    if disk_pcts and max(disk_pcts) >= 90:
        risks.append(("P0" if max(disk_pcts) >= 95 else "P1", f"Disk usage high: {max(disk_pcts)}%"))
    if has_oom_evidence:
        risks.append(("P1", "OOM or memory pressure evidence present"))
    if unlimited_containers:
        risks.append(("P1", f"{len(unlimited_containers)} Docker containers appear unlimited"))
    if ssh_password == "yes":
        risks.append(("P1", "SSH password authentication enabled"))
    if root_login in {"yes", "prohibit-password", "without-password"}:
        risks.append(("P2", f"SSH root login policy: {root_login}"))
    if public_ports:
        risks.append(("P2", f"{len(public_ports)} public listening sockets observed"))
    if not risks:
        risks.append(("P3", "No high-signal issue found by lightweight parser"))
    top_priority = sorted({p for p, _ in risks})[0]
    return {
        "host": asdict(host),
        "reachable": rc == 0,
        "return_code": rc,
        "duration_seconds": round(duration, 2),
        "roles": roles,
        "memory": mem_line,
        "swap": swap_line,
        "swappiness": swappiness,
        "disk_worst": disk_worst,
        "public_socket_count": len(public_ports),
        "unlimited_container_count": len(unlimited_containers),
        "unlimited_containers": unlimited_containers[:20],
        "oom_or_memory_pressure_evidence": has_oom_evidence,
        "ssh_password_auth": ssh_password,
        "ssh_root_login": root_login,
        "fail2ban_seen": fail2ban,
        "top_priority": top_priority,
        "risks": [{"priority": p, "text": t} for p, t in risks],
    }


def write_markdown(out_path: Path, results: list[dict[str, Any]]) -> None:
    counts = {p: sum(1 for r in results if r["top_priority"] == p) for p in ["P0", "P1", "P2", "P3"]}
    unreachable = sum(1 for r in results if not r["reachable"])
    lines = [
        "# Fleet Server Audit Summary",
        "",
        f"- Hosts checked: {len(results)}",
        f"- Unreachable or failed audits: {unreachable}",
        f"- P0/P1/P2/P3: {counts['P0']}/{counts['P1']}/{counts['P2']}/{counts['P3']}",
        "",
        "## Host Matrix",
        "",
        "| Host | Reachable | Roles | Memory | Swap | Disk | Public Sockets | Unlimited Containers | Top Risk |",
        "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for r in results:
        host = r["host"]["name"]
        top = "; ".join(f"{x['priority']}: {x['text']}" for x in r["risks"][:2])
        lines.append(
            f"| {host} | {r['reachable']} | {', '.join(r['roles'])} | "
            f"{r['memory'] or '-'} | {r['swap'] or '-'} | {r['disk_worst'] or '-'} | "
            f"{r['public_socket_count']} | {r['unlimited_container_count']} | {top} |"
        )
    lines.extend(["", "## Per-Host Notes", ""])
    for r in results:
        lines.append(f"### {r['host']['name']}")
        lines.append("")
        lines.append(f"- SSH target: `{r['host'].get('user') + '@' if r['host'].get('user') else ''}{r['host']['host']}:{r['host']['port']}`")
        lines.append(f"- Roles: {', '.join(r['roles'])}")
        lines.append(f"- Top priority: {r['top_priority']}")
        for risk in r["risks"]:
            lines.append(f"- {risk['priority']}: {risk['text']}")
        if r["unlimited_containers"]:
            lines.append(f"- Unlimited containers sample: {', '.join(r['unlimited_containers'])}")
        lines.append("")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only audit across SSH hosts.")
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--audit-script", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--default-user", default="")
    parser.add_argument("--default-port", default=22, type=int)
    parser.add_argument("--timeout", default=180, type=int)
    args = parser.parse_args()

    hosts = load_inventory(args.inventory, args.default_user, args.default_port)
    if not hosts:
        print("No hosts in inventory", file=sys.stderr)
        return 2
    audit_script = args.audit_script.read_text(encoding="utf-8")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "hosts").mkdir(exist_ok=True)
    results = []
    for host in hosts:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", host.name)
        host_dir = args.out / "hosts" / safe_name
        host_dir.mkdir(parents=True, exist_ok=True)
        print(f"==> auditing {host.name} ({host.ssh_target}:{host.port})")
        rc, stdout, stderr, duration = run_host(host, audit_script, args.timeout)
        (host_dir / "raw_audit.txt").write_text(stdout, encoding="utf-8", errors="replace")
        (host_dir / "stderr.txt").write_text(stderr, encoding="utf-8", errors="replace")
        result = analyze(host, rc, stdout, stderr, duration)
        (host_dir / "summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        results.append(result)
    (args.out / "summary.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(args.out / "summary.md", results)
    print(f"Wrote {args.out / 'summary.md'}")
    return 0 if all(r["reachable"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

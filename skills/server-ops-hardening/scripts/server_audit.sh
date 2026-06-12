#!/usr/bin/env bash
set -u

section() {
  printf '\n===== %s =====\n' "$1"
}

run() {
  printf '\n$ %s\n' "$*"
  "$@" 2>&1 || true
}

section "identity"
run hostnamectl
run uname -a
run sh -c 'cat /etc/os-release 2>/dev/null'
run systemd-detect-virt

section "uptime and boots"
run uptime
run uptime -s
run who -b
run last -x -F reboot shutdown crash -n 12
run journalctl --list-boots --no-pager

section "resources"
run nproc
run lscpu
run free -h
run swapon --show
run sysctl vm.swappiness vm.panic_on_oom vm.oom_kill_allocating_task kernel.panic_on_oops
run df -h
run df -ih
run lsblk -f

section "current pressure"
run ps -eo pid,ppid,stat,%cpu,%mem,rss,comm,args --sort=-%mem
run sh -c 'command -v vmstat >/dev/null && vmstat 1 5'
run sh -c 'command -v iostat >/dev/null && iostat -xz 1 3'

section "systemd"
run systemctl --failed --no-pager
run systemctl list-timers --all --no-pager
run systemctl list-units --type=service --state=running --no-pager

section "network exposure"
run ss -tulpn
run sh -c 'command -v ufw >/dev/null && ufw status verbose'
run sh -c 'command -v firewall-cmd >/dev/null && firewall-cmd --list-all'
run sh -c 'command -v nft >/dev/null && nft list ruleset'
run sh -c 'command -v iptables >/dev/null && iptables -S'

section "ssh and auth"
run sshd -T
run sh -c 'test -f /etc/ssh/sshd_config && sed -n "1,220p" /etc/ssh/sshd_config'
run sh -c 'getent passwd | awk -F: '\''$3 == 0 || $7 !~ /(nologin|false)$/ {print}'\'''
run sh -c 'command -v fail2ban-client >/dev/null && fail2ban-client status'
run journalctl -u ssh --since "24 hours ago" --no-pager

section "docker"
if command -v docker >/dev/null 2>&1; then
  run docker version
  run docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  run docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
  run docker stats --no-stream
  run docker system df
  run sh -c 'docker ps -q | xargs -r docker inspect --format "{{.Name}} Memory={{.HostConfig.Memory}} Swap={{.HostConfig.MemorySwap}} Pids={{.HostConfig.PidsLimit}} Privileged={{.HostConfig.Privileged}} Network={{.HostConfig.NetworkMode}} Restart={{.HostConfig.RestartPolicy.Name}} Mounts={{range .Mounts}}{{.Source}}->{{.Destination}};{{end}}"'
else
  echo "docker not found"
fi

section "logs and crash evidence"
run journalctl -p warning..emerg --since "24 hours ago" --no-pager
run sh -c 'journalctl --disk-usage'
if journalctl -b -1 -n 1 --no-pager >/dev/null 2>&1; then
  run journalctl -b -1 -n 200 --no-pager
  run sh -c 'journalctl -b -1 --no-pager | grep -Ei "oom|out of memory|killed process|memory pressure|panic|watchdog|soft lockup|hard lockup|blocked for more|i/o error|ext4|nvme|read-only|thermal|segfault"'
fi

section "updates"
run sh -c 'command -v apt >/dev/null && apt list --upgradable 2>/dev/null | sed -n "1,80p"'
run sh -c 'command -v dnf >/dev/null && dnf check-update'
run sh -c 'command -v yum >/dev/null && yum check-update'

section "secret exposure quick check"
run sh -c 'find /root /home /opt /app -maxdepth 3 -type f \( -name ".env" -o -name "*.key" -o -name "id_rsa" -o -name "docker-compose.yml" -o -name "docker-compose.yaml" \) 2>/dev/null | sed -n "1,120p"'

section "done"
date -Is

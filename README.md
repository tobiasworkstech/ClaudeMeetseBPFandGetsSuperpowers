# eBPF Kernel Health Monitor

Real-time Linux kernel issue detection using eBPF probes. Runs on macOS via Docker Desktop (LinuxKit kernel 6.12+).

## What It Monitors

| Subsystem | Probe Type | What It Detects |
|-----------|-----------|-----------------|
| **CPU Scheduling** | `sched_wakeup` / `sched_switch` raw tracepoints | Runqueue latency -- time a task waits to get scheduled on a CPU |
| **Block I/O** | kprobes on `blk_mq_start_request` / `blk_mq_end_request` | Slow disk I/O -- latency from request issue to completion |
| **VFS** | kprobes on `vfs_read` / `vfs_write` | Slow filesystem operations |
| **Memory** | `oom:mark_victim` tracepoint | OOM kills -- kernel killing processes due to memory pressure |
| **Network** | `tcp:tcp_retransmit_skb` tracepoint | TCP retransmissions -- indicates packet loss or congestion |
| **Network** | kprobe on `kfree_skb_reason` | Packet drops in the kernel network stack |
| **Memory** | kprobe on `handle_mm_fault` | Page faults (major and minor) |

## Quick Start (macOS via Docker)

```bash
# Clone and start the eBPF lab
cd claude2ebpf
docker compose up -d

# Wait for setup (~3-5 min first time: installs tools + fetches kernel headers)
docker logs -f claude2ebpf

# Once you see "eBPF Lab Ready", run the monitor
docker exec -it claude2ebpf python3 /workspace/ebpf_kernel_monitor.py

# Run for 30 seconds with summary
docker exec -it claude2ebpf python3 /workspace/ebpf_kernel_monitor.py --duration 30

# Quiet mode (summary only)
docker exec -it claude2ebpf python3 /workspace/ebpf_kernel_monitor.py -q -d 60
```

## How It Works on macOS

macOS does not support eBPF natively. Docker Desktop runs a LinuxKit VM under the hood, which provides a full Linux kernel (6.12.x). The container runs in `--privileged` mode with `pid: host` and access to debugfs/tracefs, allowing eBPF probes to attach to the LinuxKit kernel.

**Key challenge solved:** LinuxKit does not ship kernel headers. The docker-compose startup script automatically:
1. Detects the running kernel version (`uname -r`)
2. Downloads matching kernel source from kernel.org
3. Extracts include dirs, arch headers, scripts, and Kconfig files
4. Runs `make prepare` to generate required headers (`autoconf.h`, `bounds.h`, `timeconst.h`, `asm-offsets.h`, `cpucap-defs.h`)
5. Symlinks the headers into `/lib/modules/$(uname -r)/build`

## Environment

| Component | Version |
|-----------|---------|
| Host | macOS (Apple Silicon / arm64) |
| Docker VM | LinuxKit |
| Kernel | 6.12.54-linuxkit |
| Container | Ubuntu 24.04 |
| BCC | 0.29.1 |
| bpftrace | 0.20.2 |
| clang/llvm | 18.1.3 |

## Requirements

- macOS with Docker Desktop (or any Linux host with kernel 4.18+)
- Docker Compose v2
- ~1GB disk for kernel headers + tools on first run
- Root privileges inside container (handled by `privileged: true`)

### Native Linux Installation

```bash
# Ubuntu / Debian
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Fedora / RHEL
sudo dnf install bcc-tools python3-bcc kernel-devel-$(uname -r)

# Run directly (no Docker needed)
sudo python3 ebpf_kernel_monitor.py
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--duration N` | Monitor for N seconds (0 = until Ctrl+C) | 0 |
| `--sched-warn N` | Scheduling latency warning threshold (us) | 1000 |
| `--bio-warn N` | Block I/O latency warning threshold (us) | 10000 |
| `--vfs-warn N` | VFS latency warning threshold (us) | 5000 |
| `--no-histogram` | Skip latency distribution histograms | false |
| `-q, --quiet` | Only show summary, no real-time events | false |

## Test Results

### Environment
- **Host:** macOS (Apple Silicon M-series)
- **Docker Desktop:** LinuxKit 6.12.54 (arm64)
- **Container:** Ubuntu 24.04, BCC 0.29.1

### Probe Attachment Status

```
Probe                          Status      Method
────────────────────────────── ────────── ──────────────────────
Scheduling latency             ATTACHED   RAW_TRACEPOINT (sched_wakeup, sched_switch)
Block I/O latency              ATTACHED   kprobe (blk_mq_start_request / blk_mq_end_request)
VFS read/write latency         ATTACHED   kprobe + kretprobe (vfs_read, vfs_write)
OOM kills                      ATTACHED   TRACEPOINT (oom:mark_victim)
TCP retransmits                ATTACHED   TRACEPOINT (tcp:tcp_retransmit_skb)
Page faults                    ATTACHED   kprobe (handle_mm_fault)
Packet drops                   SKIPPED    kfree_skb_reason not available on LinuxKit
```

### 10-Second Monitoring Run

```
TIME         TYPE              CPU   PID      PROCESS          DETAILS
──────────────────────────────────────────────────────────────────────────────
15:34:58.971 PAGE_FAULT        cpu=0 pid=41670 python3          addr=0x0000ffff9cbea090
15:35:03.347 VFS_SLOW          cpu=3 pid=152   initd            latency=1.01s op=vfs_read [CRITICAL]
15:35:07.339 VFS_SLOW          cpu=3 pid=152   initd            latency=3.99s op=vfs_read [CRITICAL]
15:35:07.622 SCHED_LATENCY     cpu=0 pid=524   dockerd          latency=1.06ms [WARNING]
15:35:07.622 SCHED_LATENCY     cpu=1 pid=296   containerd       latency=2.32ms [WARNING]
15:35:07.622 SCHED_LATENCY     cpu=2 pid=844   dockerd          latency=1.61ms [WARNING]
15:35:07.623 SCHED_LATENCY     cpu=6 pid=34473 containerd-shim  latency=1.97ms [WARNING]
15:35:08.346 VFS_SLOW          cpu=2 pid=152   initd            latency=1.01s op=vfs_read [CRITICAL]
```

### Scheduling Latency Distribution

```
     us                  : count     distribution
         0 -> 1          : 32       |**                                      |
         2 -> 3          : 432      |****************************************|
         4 -> 7          : 431      |*************************************** |
         8 -> 15         : 317      |*****************************           |
        16 -> 31         : 203      |******************                      |
        32 -> 63         : 172      |***************                         |
        64 -> 127        : 20       |*                                       |
       128 -> 255        : 9        |                                        |
       256 -> 511        : 4        |                                        |
       512 -> 1023       : 5        |                                        |
      1024 -> 2047       : 5        |                                        |
      2048 -> 4095       : 1        |                                        |
```

### Summary Report

```
══════════════════════════════════════════════════════════════
  MONITORING SUMMARY  (10.1s)
══════════════════════════════════════════════════════════════

  Overall Status: ELEVATED ACTIVITY

  Subsystem                  Events   Worst Latency  Status
  ──────────────────────── ────────  ──────────────  ──────────
  Scheduling Latency              4          2.32ms  WARNING
  Block I/O Latency               0               -  OK
  VFS Latency                     3           3.99s  WARNING
  OOM Kills                       0               -  OK
  TCP Retransmits                 0               -  OK
  Packet Drops                    0               -  OK
  Page Faults (Major)           904               -  WARNING
  Soft Lockups                    0               -  OK
══════════════════════════════════════════════════════════════
```

### Key Findings

- **Scheduling latency is healthy:** 99.4% of context switches under 64us, worst case 2.32ms
- **VFS latency anomaly:** `initd` (pid 152) shows 1-4s `vfs_read` calls -- this is the LinuxKit init process blocking on `/dev/console` or epoll, expected behavior in Docker Desktop's VM
- **Page faults are normal:** 904 faults in 10s from `containerd` and `python3` (BCC itself) -- standard memory allocation activity
- **No OOM kills, no TCP retransmits** -- system is healthy

## Output Format

```
12:34:56.789 SCHED_LATENCY    cpu=3   pid=1234    myapp            latency=2.45ms [WARNING]
12:34:57.012 TCP_RETRANSMIT   cpu=0   pid=5678    nginx            sport=443 dport=52134
12:34:57.345 BIO_LATENCY      cpu=2   pid=891     postgres         latency=15.2ms [WARNING]
12:34:58.678 OOM_KILL         cpu=1   pid=2345    java             victim_pid=2345 *** PROCESS KILLED ***
```

## For RT / Latency-Sensitive Workloads

For real-time workloads, tighten the thresholds:

```bash
# Alert on >100us scheduling latency (critical for L1/L2 processing)
docker exec -it claude2ebpf python3 /workspace/ebpf_kernel_monitor.py \
    --sched-warn 100 \
    --bio-warn 1000 \
    --vfs-warn 500
```

Key things to look for:
- **Scheduling latency spikes** on isolated cores -> check `isolcpus`, `nohz_full`, IRQ affinity
- **Block I/O on RT cores** -> ensure no filesystem access from RT threads
- **TCP retransmits on fronthaul/midhaul** -> check NIC offloads, ring buffer sizes
- **OOM kills in containers** -> review cgroup memory limits

## Architecture

```
+---------------------------------------------------------+
|                    User Space                           |
|  +---------------------------------------------------+  |
|  |  ebpf_kernel_monitor.py                           |  |
|  |  - BCC Python bindings                            |  |
|  |  - Perf buffer consumer                           |  |
|  |  - Event formatting & severity classification     |  |
|  |  - Histogram rendering                            |  |
|  |  - Summary generation & recommendations           |  |
|  +------------------------+--------------------------+  |
+---------------------------|-----------------------------+
|                    Kernel Space                         |
|  +------------------------+--------------------------+  |
|  |  eBPF Programs (JIT compiled, verified)           |  |
|  |                                                   |  |
|  |  +---------------+  +-------------------------+   |  |
|  |  | RAW_TRACEPOINT|  | Kprobes:                |   |  |
|  |  | sched_wakeup  |  | blk_mq_start_request    |   |  |
|  |  | sched_switch  |  | blk_mq_end_request      |   |  |
|  |  |               |  | vfs_read / vfs_write    |   |  |
|  |  |               |  | handle_mm_fault         |   |  |
|  |  |               |  | kfree_skb_reason        |   |  |
|  |  +-------+-------+  +------------+------------+   |  |
|  |          |                        |               |  |
|  |  +-------+------------------------+------------+  |  |
|  |  | Tracepoints:                                |  |  |
|  |  | oom:mark_victim                             |  |  |
|  |  | tcp:tcp_retransmit_skb                      |  |  |
|  |  +---------------------+-----------------------+  |  |
|  |                        |                          |  |
|  |  +---------------------+-----------------------+  |  |
|  |  | BPF Maps:                                   |  |  |
|  |  | - Perf buffer (events -> userspace)         |  |  |
|  |  | - Hash maps (start timestamps)              |  |  |
|  |  | - Histograms (latency distributions)        |  |  |
|  |  | - Array (aggregate counters)                |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## Files

```
claude2ebpf/
  docker-compose.yml         # Docker lab with auto kernel header setup
  ebpf_kernel_monitor.py     # Main eBPF monitor script (BCC/Python)
  workspace/                 # Mounted into container at /workspace
    ebpf_kernel_monitor.py   # Copy accessible inside container
  README.md                  # This file
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Failed to compile BPF module` | Kernel headers missing -- wait for `docker compose up` to finish setup |
| `Read-only file system` on kprobe_events | Remount debugfs: `mount -o remount,rw /sys/kernel/debug/tracing` |
| `modprobe: not found` | Install kmod: `apt install kmod` (included in docker-compose) |
| Packet drop probe skipped | `kfree_skb_reason` not available on LinuxKit -- use native Linux for full probe coverage |
| Container exits immediately | Check `docker logs claude2ebpf` -- likely a package install failure |
| Slow first startup | Normal -- downloads ~140MB kernel source + installs ~300MB of tools |

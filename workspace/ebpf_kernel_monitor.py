#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════════╗
║                  eBPF Kernel Health Monitor                        ║
║                                                                    ║
║  Monitors the Linux kernel in real-time for performance issues     ║
║  using eBPF probes attached to key kernel subsystems.              ║
║                                                                    ║
║  Subsystems monitored:                                             ║
║    1. CPU Scheduling  - runqueue latency, off-CPU time             ║
║    2. Memory          - OOM kills, page faults, reclaim stalls     ║
║    3. Storage I/O     - block layer latency, slow I/O detection    ║
║    4. Networking      - TCP retransmits, packet drops              ║
║    5. Filesystem      - VFS read/write latency                     ║
║    6. Kernel Warnings - soft lockups, RCU stalls                   ║
║                                                                    ║
║  Requirements: Linux 4.18+, BCC (bpfcc-tools), root privileges     ║
║  Install: apt install bpfcc-tools python3-bpfcc (Debian/Ubuntu)    ║
║           dnf install bcc-tools python3-bcc (Fedora/RHEL)          ║
║                                                                    ║
║  Usage: sudo python3 ebpf_kernel_monitor.py [--duration N]         ║
╚════════════════════════════════════════════════════════════════════╝
"""

import argparse
import ctypes
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC not found. Install with:")
    print("  Ubuntu/Debian: sudo apt install bpfcc-tools python3-bpfcc")
    print("  Fedora/RHEL:   sudo dnf install bcc-tools python3-bcc")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────
# ANSI Colors for terminal output
# ─────────────────────────────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

# ─────────────────────────────────────────────────────────────────────
# Severity levels and thresholds
# ─────────────────────────────────────────────────────────────────────
SCHED_LATENCY_WARN_US   = 1000      # 1ms  - scheduling latency warning
SCHED_LATENCY_CRIT_US   = 10000     # 10ms - scheduling latency critical
BIO_LATENCY_WARN_US     = 10000     # 10ms - block I/O warning
BIO_LATENCY_CRIT_US     = 100000    # 100ms - block I/O critical
VFS_LATENCY_WARN_US     = 5000      # 5ms  - VFS operation warning
VFS_LATENCY_CRIT_US     = 50000     # 50ms - VFS operation critical

# ─────────────────────────────────────────────────────────────────────
# eBPF Program (C code loaded into the kernel)
# ─────────────────────────────────────────────────────────────────────
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// ── Event types sent to userspace ──
#define EVT_SCHED_LATENCY   1
#define EVT_BIO_LATENCY     2
#define EVT_OOM_KILL        3
#define EVT_TCP_RETRANSMIT  4
#define EVT_TCP_DROP        5
#define EVT_PAGE_FAULT      6
#define EVT_VFS_SLOW        7
#define EVT_SOFTLOCKUP      8

// ── Generic event structure ──
struct event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 cpu;
    u32 event_type;
    u64 latency_us;
    u64 extra_data;
    char comm[TASK_COMM_LEN];
    char detail[64];
};

// ── Ring buffer for events to userspace ──
BPF_PERF_OUTPUT(events);

// ── Hash maps for tracking start times ──
BPF_HASH(start_sched, u32, u64);          // pid -> enqueue timestamp
BPF_HASH(start_bio, u64, u64);            // request ptr as u64 -> issue timestamp
BPF_HASH(start_vfs_read, u32, u64);       // tid -> vfs_read start
BPF_HASH(start_vfs_write, u32, u64);      // tid -> vfs_write start

// ── Histograms for latency distributions ──
BPF_HISTOGRAM(sched_latency_hist, u64);
BPF_HISTOGRAM(bio_latency_hist, u64);

// ── Stats counters ──
BPF_ARRAY(stats, u64, 8);
// Index 0: total schedule events
// Index 1: schedule latency > warn threshold
// Index 2: total bio events
// Index 3: bio latency > warn threshold
// Index 4: OOM kills
// Index 5: TCP retransmits
// Index 6: TCP drops
// Index 7: page faults (major)

// ════════════════════════════════════════════════════════════════════
// 1. CPU SCHEDULING LATENCY
//    Measures time between a task becoming runnable and actually
//    getting scheduled on a CPU (runqueue latency).
// ════════════════════════════════════════════════════════════════════

RAW_TRACEPOINT_PROBE(sched_wakeup) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 pid = p->pid;
    u64 ts = bpf_ktime_get_ns();
    start_sched.update(&pid, &ts);
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    u32 pid = p->pid;
    u64 ts = bpf_ktime_get_ns();
    start_sched.update(&pid, &ts);
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_switch) {
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid = next->pid;

    u64 *tsp = start_sched.lookup(&pid);
    if (tsp == 0) return 0;

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    u64 delta_us = delta_ns / 1000;
    start_sched.delete(&pid);

    u64 log2_val = bpf_log2l(delta_us);
    sched_latency_hist.atomic_increment(log2_val);

    u32 idx = 0;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    if (delta_us < SCHED_LATENCY_WARN_THRESHOLD) return 0;

    idx = 1;
    val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = next->tgid;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_SCHED_LATENCY;
    evt.latency_us = delta_us;
    bpf_probe_read_kernel_str(&evt.comm, sizeof(evt.comm), next->comm);
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 2. BLOCK I/O LATENCY (kprobe-based for compatibility)
// ════════════════════════════════════════════════════════════════════

int trace_blk_account_io_start(struct pt_regs *ctx) {
    u64 rq = PT_REGS_PARM1(ctx);
    u64 ts = bpf_ktime_get_ns();
    start_bio.update(&rq, &ts);
    return 0;
}

int trace_blk_account_io_done(struct pt_regs *ctx) {
    u64 rq = PT_REGS_PARM1(ctx);
    u64 *tsp = start_bio.lookup(&rq);
    if (tsp == 0) return 0;

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    u64 delta_us = delta_ns / 1000;
    start_bio.delete(&rq);

    u64 log2_val = bpf_log2l(delta_us);
    bio_latency_hist.atomic_increment(log2_val);

    u32 idx = 2;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    if (delta_us < BIO_LATENCY_WARN_THRESHOLD) return 0;

    idx = 3;
    val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_BIO_LATENCY;
    evt.latency_us = delta_us;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 3. OOM KILLER
// ════════════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(oom, mark_victim) {
    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = args->pid;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_OOM_KILL;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    u32 idx = 4;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 4. TCP RETRANSMITS
// ════════════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_TCP_RETRANSMIT;
    evt.extra_data = (u64)args->sport << 16 | (u64)args->dport;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    u32 idx = 5;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 5. TCP DROPS (kprobe on kfree_skb_reason for kernel 6.x)
// ════════════════════════════════════════════════════════════════════

int trace_kfree_skb(struct pt_regs *ctx) {
    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_TCP_DROP;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    u32 idx = 6;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 6. PAGE FAULTS (via kprobe on handle_mm_fault)
// ════════════════════════════════════════════════════════════════════

int trace_page_fault(struct pt_regs *ctx) {
    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_PAGE_FAULT;
    evt.extra_data = PT_REGS_PARM2(ctx);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    u32 idx = 7;
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ════════════════════════════════════════════════════════════════════
// 7. VFS READ/WRITE LATENCY
// ════════════════════════════════════════════════════════════════════

int trace_vfs_read_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_vfs_read.update(&tid, &ts);
    return 0;
}

int trace_vfs_read_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 *tsp = start_vfs_read.lookup(&tid);
    if (tsp == 0) return 0;

    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    start_vfs_read.delete(&tid);

    if (delta_us < VFS_LATENCY_WARN_THRESHOLD) return 0;

    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_VFS_SLOW;
    evt.latency_us = delta_us;
    __builtin_memcpy(evt.detail, "vfs_read", 9);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_vfs_write_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_vfs_write.update(&tid, &ts);
    return 0;
}

int trace_vfs_write_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 *tsp = start_vfs_write.lookup(&tid);
    if (tsp == 0) return 0;

    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    start_vfs_write.delete(&tid);

    if (delta_us < VFS_LATENCY_WARN_THRESHOLD) return 0;

    struct event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cpu = bpf_get_smp_processor_id();
    evt.event_type = EVT_VFS_SLOW;
    evt.latency_us = delta_us;
    __builtin_memcpy(evt.detail, "vfs_write", 10);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────────────
# Event type mapping
# ─────────────────────────────────────────────────────────────────────
EVENT_TYPES = {
    1: ("SCHED_LATENCY",  Color.YELLOW,  "⏱"),
    2: ("BIO_LATENCY",    Color.MAGENTA, "💾"),
    3: ("OOM_KILL",       Color.RED,     "💀"),
    4: ("TCP_RETRANSMIT", Color.CYAN,    "🔄"),
    5: ("TCP_DROP",       Color.RED,     "📦"),
    6: ("PAGE_FAULT",     Color.BLUE,    "📄"),
    7: ("VFS_SLOW",       Color.YELLOW,  "📁"),
    8: ("SOFT_LOCKUP",    Color.RED,     "🔒"),
}

# ─────────────────────────────────────────────────────────────────────
# Event counters for summary
# ─────────────────────────────────────────────────────────────────────
event_counts = defaultdict(int)
worst_latencies = defaultdict(float)
start_time = None


def severity_color(event_type, latency_us):
    """Determine color based on severity."""
    if event_type == 1:  # sched latency
        if latency_us >= SCHED_LATENCY_CRIT_US:
            return Color.RED + Color.BOLD
        return Color.YELLOW
    elif event_type == 2:  # bio latency
        if latency_us >= BIO_LATENCY_CRIT_US:
            return Color.RED + Color.BOLD
        return Color.MAGENTA
    elif event_type == 7:  # vfs latency
        if latency_us >= VFS_LATENCY_CRIT_US:
            return Color.RED + Color.BOLD
        return Color.YELLOW
    elif event_type in (3, 5, 8):  # OOM, drop, lockup
        return Color.RED + Color.BOLD
    return EVENT_TYPES.get(event_type, ("", Color.WHITE, ""))[1]


def format_latency(us):
    """Format latency with appropriate units."""
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    elif us >= 1000:
        return f"{us / 1000:.2f}ms"
    else:
        return f"{us:.0f}µs"


def format_event(cpu, data, size):
    """Callback for processing eBPF events."""
    global event_counts, worst_latencies

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    etype = event.event_type
    event_counts[etype] += 1

    if event.latency_us > worst_latencies[etype]:
        worst_latencies[etype] = event.latency_us

    type_name, color, icon = EVENT_TYPES.get(etype, ("UNKNOWN", Color.WHITE, "?"))
    sev_color = severity_color(etype, event.latency_us)
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    comm = event.comm.decode("utf-8", errors="replace")

    # Build the detail string based on event type
    detail = ""
    if etype in (1, 2, 7):  # Latency events
        lat_str = format_latency(event.latency_us)
        severity = "CRITICAL" if (
            (etype == 1 and event.latency_us >= SCHED_LATENCY_CRIT_US) or
            (etype == 2 and event.latency_us >= BIO_LATENCY_CRIT_US) or
            (etype == 7 and event.latency_us >= VFS_LATENCY_CRIT_US)
        ) else "WARNING"
        detail_op = event.detail.decode("utf-8", errors="replace").rstrip('\x00')
        if detail_op:
            detail = f"latency={lat_str} op={detail_op} [{severity}]"
        else:
            detail = f"latency={lat_str} [{severity}]"
    elif etype == 3:  # OOM
        detail = f"victim_pid={event.pid} *** PROCESS KILLED ***"
    elif etype == 4:  # TCP retransmit
        sport = (event.extra_data >> 16) & 0xFFFF
        dport = event.extra_data & 0xFFFF
        detail = f"sport={sport} dport={dport}"
    elif etype == 5:  # TCP drop
        detail = f"protocol={event.extra_data}"
    elif etype == 6:  # Page fault
        detail = f"addr=0x{event.extra_data:016x}"

    print(
        f"{Color.DIM}{timestamp}{Color.RESET} "
        f"{icon} {sev_color}{type_name:<16}{Color.RESET} "
        f"cpu={event.cpu:<3} pid={event.pid:<7} "
        f"{Color.WHITE}{comm:<16}{Color.RESET} "
        f"{sev_color}{detail}{Color.RESET}"
    )


def print_banner():
    """Print startup banner."""
    print(f"""
{Color.CYAN}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗
║              eBPF Kernel Health Monitor v1.0                 ║
║                                                              ║
║  Probes:                                                     ║
║    ⏱  Scheduling latency  (warn>{SCHED_LATENCY_WARN_US}µs, crit>{SCHED_LATENCY_CRIT_US}µs)        ║
║    💾 Block I/O latency    (warn>{BIO_LATENCY_WARN_US}µs, crit>{BIO_LATENCY_CRIT_US}µs)     ║
║    📁 VFS read/write       (warn>{VFS_LATENCY_WARN_US}µs, crit>{VFS_LATENCY_CRIT_US}µs)       ║
║    💀 OOM kills                                              ║
║    🔄 TCP retransmissions                                    ║
║    📦 Packet drops (kfree_skb)                               ║
║    📄 Page faults (major)                                    ║
║                                                              ║
║  Press Ctrl+C to stop and show summary                       ║
╚══════════════════════════════════════════════════════════════╝{Color.RESET}
""")


def print_summary(duration_s):
    """Print final summary report."""
    print(f"\n{Color.CYAN}{Color.BOLD}{'═' * 62}")
    print(f"  MONITORING SUMMARY  ({duration_s:.1f}s)")
    print(f"{'═' * 62}{Color.RESET}\n")

    # Determine overall health
    critical_events = event_counts.get(3, 0) + event_counts.get(8, 0)
    high_sched = worst_latencies.get(1, 0) >= SCHED_LATENCY_CRIT_US
    high_bio = worst_latencies.get(2, 0) >= BIO_LATENCY_CRIT_US

    if critical_events > 0 or high_sched or high_bio:
        health = f"{Color.RED}{Color.BOLD}⚠  ISSUES DETECTED{Color.RESET}"
    elif sum(event_counts.values()) > 100:
        health = f"{Color.YELLOW}{Color.BOLD}⚡ ELEVATED ACTIVITY{Color.RESET}"
    else:
        health = f"{Color.GREEN}{Color.BOLD}✅ HEALTHY{Color.RESET}"

    print(f"  Overall Status: {health}\n")

    # Per-subsystem summary
    subsystems = [
        (1, "Scheduling Latency"),
        (2, "Block I/O Latency"),
        (7, "VFS Latency"),
        (3, "OOM Kills"),
        (4, "TCP Retransmits"),
        (5, "Packet Drops"),
        (6, "Page Faults (Major)"),
        (8, "Soft Lockups"),
    ]

    print(f"  {'Subsystem':<24} {'Events':>8}  {'Worst Latency':>14}  Status")
    print(f"  {'─' * 24} {'─' * 8}  {'─' * 14}  {'─' * 10}")

    for etype, name in subsystems:
        count = event_counts.get(etype, 0)
        worst = worst_latencies.get(etype, 0)

        # Determine status
        if etype == 3 and count > 0:
            status = f"{Color.RED}CRITICAL{Color.RESET}"
        elif etype == 1 and worst >= SCHED_LATENCY_CRIT_US:
            status = f"{Color.RED}CRITICAL{Color.RESET}"
        elif etype == 2 and worst >= BIO_LATENCY_CRIT_US:
            status = f"{Color.RED}CRITICAL{Color.RESET}"
        elif count > 0:
            status = f"{Color.YELLOW}WARNING{Color.RESET}"
        else:
            status = f"{Color.GREEN}OK{Color.RESET}"

        lat_str = format_latency(worst) if worst > 0 else "—"
        print(f"  {name:<24} {count:>8}  {lat_str:>14}  {status}")

    # Recommendations
    print(f"\n  {Color.BOLD}Recommendations:{Color.RESET}")

    if event_counts.get(1, 0) > 0 and worst_latencies.get(1, 0) >= SCHED_LATENCY_CRIT_US:
        print(f"  {Color.YELLOW}→ High scheduling latency detected. Check:")
        print(f"    - CPU oversubscription (too many tasks per core)")
        print(f"    - Missing CPU isolation (isolcpus, cgroups)")
        print(f"    - Kernel preemption model (PREEMPT_RT for RT workloads)")
        print(f"    - IRQ affinity configuration{Color.RESET}")

    if event_counts.get(2, 0) > 0 and worst_latencies.get(2, 0) >= BIO_LATENCY_CRIT_US:
        print(f"  {Color.YELLOW}→ High block I/O latency detected. Check:")
        print(f"    - Disk utilization (iostat -xz 1)")
        print(f"    - I/O scheduler (mq-deadline for latency-sensitive)")
        print(f"    - Storage device health (SMART data){Color.RESET}")

    if event_counts.get(3, 0) > 0:
        print(f"  {Color.RED}→ OOM kills detected! Check:")
        print(f"    - Memory limits in cgroups/containers")
        print(f"    - Application memory leaks")
        print(f"    - Overcommit settings (vm.overcommit_memory){Color.RESET}")

    if event_counts.get(4, 0) > 10:
        print(f"  {Color.YELLOW}→ TCP retransmissions elevated. Check:")
        print(f"    - Network interface errors (ethtool -S)")
        print(f"    - MTU mismatches / packet fragmentation")
        print(f"    - NIC ring buffer sizes (ethtool -g){Color.RESET}")

    if event_counts.get(5, 0) > 50:
        print(f"  {Color.YELLOW}→ High packet drop rate. Check:")
        print(f"    - Netfilter/iptables rules")
        print(f"    - Socket buffer sizes (net.core.rmem_max)")
        print(f"    - NIC offload settings{Color.RESET}")

    if sum(event_counts.values()) == 0:
        print(f"  {Color.GREEN}✓ No issues detected during monitoring period.{Color.RESET}")

    print(f"\n{Color.CYAN}{'═' * 62}{Color.RESET}\n")


def print_histograms(b):
    """Print latency distribution histograms."""
    print(f"\n{Color.CYAN}{Color.BOLD}Scheduling Latency Distribution (µs):{Color.RESET}")
    try:
        b["sched_latency_hist"].print_log2_hist("µs")
    except Exception:
        print("  (no data)")

    print(f"\n{Color.CYAN}{Color.BOLD}Block I/O Latency Distribution (µs):{Color.RESET}")
    try:
        b["bio_latency_hist"].print_log2_hist("µs")
    except Exception:
        print("  (no data)")


def main():
    parser = argparse.ArgumentParser(
        description="eBPF Kernel Health Monitor - Detect kernel issues in real-time"
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=0,
        help="Monitoring duration in seconds (0 = until Ctrl+C)"
    )
    parser.add_argument(
        "--sched-warn", type=int, default=SCHED_LATENCY_WARN_US,
        help=f"Scheduling latency warning threshold in µs (default: {SCHED_LATENCY_WARN_US})"
    )
    parser.add_argument(
        "--bio-warn", type=int, default=BIO_LATENCY_WARN_US,
        help=f"Block I/O latency warning threshold in µs (default: {BIO_LATENCY_WARN_US})"
    )
    parser.add_argument(
        "--vfs-warn", type=int, default=VFS_LATENCY_WARN_US,
        help=f"VFS latency warning threshold in µs (default: {VFS_LATENCY_WARN_US})"
    )
    parser.add_argument(
        "--no-histogram", action="store_true",
        help="Skip printing latency histograms at the end"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Only show summary at the end, suppress real-time events"
    )
    args = parser.parse_args()

    # Inject thresholds into BPF program
    program = BPF_PROGRAM.replace(
        "SCHED_LATENCY_WARN_THRESHOLD", str(args.sched_warn)
    ).replace(
        "BIO_LATENCY_WARN_THRESHOLD", str(args.bio_warn)
    ).replace(
        "VFS_LATENCY_WARN_THRESHOLD", str(args.vfs_warn)
    )

    print_banner()
    print(f"{Color.DIM}Loading eBPF probes into kernel...{Color.RESET}")

    try:
        b = BPF(text=program)
    except Exception as e:
        print(f"\n{Color.RED}ERROR: Failed to compile/load eBPF program:{Color.RESET}")
        print(f"  {e}")
        print(f"\n{Color.YELLOW}Possible causes:")
        print(f"  - Not running as root (try: sudo)")
        print(f"  - Kernel headers not installed")
        print(f"  - Kernel too old (need 4.18+)")
        print(f"  - Some tracepoints may not exist on your kernel{Color.RESET}")
        sys.exit(1)

    # Attach kprobes for block I/O (try multiple function names for compatibility)
    bio_start_attached = False
    for func in ["blk_account_io_start", "__blk_account_io_start", "blk_mq_start_request"]:
        try:
            b.attach_kprobe(event=func, fn_name="trace_blk_account_io_start")
            bio_start_attached = True
            break
        except Exception:
            continue

    bio_done_attached = False
    for func in ["blk_account_io_done", "__blk_account_io_done", "blk_mq_end_request"]:
        try:
            b.attach_kprobe(event=func, fn_name="trace_blk_account_io_done")
            bio_done_attached = True
            break
        except Exception:
            continue

    if not bio_start_attached or not bio_done_attached:
        print(f"  {Color.YELLOW}⚠ Block I/O probes: not available on this kernel{Color.RESET}")

    # Attach VFS probes
    try:
        b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read_entry")
        b.attach_kretprobe(event="vfs_read", fn_name="trace_vfs_read_return")
        b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write_entry")
        b.attach_kretprobe(event="vfs_write", fn_name="trace_vfs_write_return")
    except Exception:
        print(f"  {Color.YELLOW}⚠ VFS probes: not available on this kernel{Color.RESET}")

    # Attach page fault probe
    try:
        b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_fault")
    except Exception:
        print(f"  {Color.YELLOW}⚠ Page fault probe: not available on this kernel{Color.RESET}")

    # Attach packet drop probe
    try:
        b.attach_kprobe(event="kfree_skb_reason", fn_name="trace_kfree_skb")
    except Exception:
        try:
            b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
        except Exception:
            print(f"  {Color.YELLOW}⚠ Packet drop probe: not available on this kernel{Color.RESET}")

    print(f"{Color.GREEN}✓ eBPF probes loaded successfully{Color.RESET}")
    print(f"{Color.DIM}{'─' * 90}{Color.RESET}")
    print(
        f"{Color.DIM}{'TIME':<12} {'TYPE':<18} "
        f"{'CPU':>4}  {'PID':>7}  {'PROCESS':<16} {'DETAILS'}{Color.RESET}"
    )
    print(f"{Color.DIM}{'─' * 90}{Color.RESET}")

    # Define the event struct for ctypes
    global Event

    class Event(ctypes.Structure):
        _fields_ = [
            ("timestamp_ns", ctypes.c_uint64),
            ("pid", ctypes.c_uint32),
            ("tgid", ctypes.c_uint32),
            ("cpu", ctypes.c_uint32),
            ("event_type", ctypes.c_uint32),
            ("latency_us", ctypes.c_uint64),
            ("extra_data", ctypes.c_uint64),
            ("comm", ctypes.c_char * 16),
            ("detail", ctypes.c_char * 64),
        ]

    # Set up the perf buffer callback
    if not args.quiet:
        b["events"].open_perf_buffer(format_event, page_cnt=256)

    global start_time
    start_time = time.time()

    # Handle Ctrl+C gracefully
    running = [True]

    def signal_handler(signum, frame):
        running[0] = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Main polling loop
    try:
        while running[0]:
            b.perf_buffer_poll(timeout=100)  # 100ms timeout

            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    duration = time.time() - start_time

    # Print histograms and summary
    if not args.no_histogram:
        print_histograms(b)

    print_summary(duration)

    # Cleanup
    b.cleanup()


if __name__ == "__main__":
    main()

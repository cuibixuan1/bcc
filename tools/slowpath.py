#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# slowpatch     Trace slowpath of page alloc
#
# USAGE: slowpatch [-h] [-p PID] [-t TID] [min_order]
#
# Copyright (c) 2024 vivo, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Jun-2024   Bixuan Cui   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import os

# arguments
examples = """examples:
    ./slowpatch           # trace all alloc pages
    ./slowpatch 4         # trace order more than or equal to 4
    ./slowpatch -p 123    # trace pid 123
    ./slowpatch -t 123    # trace tid 123 (use for threads only)
"""
parser = argparse.ArgumentParser(
    description="Trace alloc pages",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("min_order", nargs="?", default='0',
    help="minimum order of alloc (default 0)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", metavar="PID", dest="pid",
    help="trace this PID only", type=int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="tid",
    help="trace this TID only", type=int)
args = parser.parse_args()

min_order = int(args.min_order)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>

struct data_t {
    u32 pid;
    u32 tid;
    char task[TASK_COMM_LEN];
    u32 order;
    u64 delta_us;
    int fastpath;
};

struct start_t {
    unsigned int order;
    u64 ts;
};

BPF_ARRAY(start, struct start_t, MAX_PID);
BPF_PERF_OUTPUT(events);

// store timestamp and order on entry
static int trace_enqueue(u32 tgid, u32 pid, unsigned int order)
{
    if (FILTER_PID || FILTER_TGID || pid == 0)
        return 0;

    struct start_t val = {0};
    val.order = order;
    val.ts = bpf_ktime_get_ns();

    start.update(&pid, &val);
    return 0;
}

int trace_slowpath_entry(struct pt_regs *ctx, gfp_t gfp_mask, 
    unsigned int order, struct alloc_context *ac)
{
    u32 tgid = bpf_get_current_pid_tgid();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    return trace_enqueue(tgid, pid, order);
}

int trace_slowpath_exit(struct pt_regs *ctx)
{
    u64 delta_us;
    u32 tgid = bpf_get_current_pid_tgid();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct start_t *val = start.lookup(&pid);
    if ((val == 0) || (val->ts == 0)) {
        return 0;   // missed enqueue
    }

    delta_us = (bpf_ktime_get_ns() - val->ts) / 1000;

    struct data_t data = {};
    data.pid = tgid;
    data.tid = pid;
    data.delta_us = delta_us;
    data.order = val->order;
    data.fastpath = 1;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    val->ts = 0;
    return 0;
}
"""

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
if args.tid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.tid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')

if args.pid:
    bpf_text = bpf_text.replace('FILTER_TGID', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_TGID', '0')

max_pid = int(open("/proc/sys/kernel/pid_max").read())

b = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])
#b.attach_kprobe(event="__alloc_pages_slowpath", fn_name="trace_slowpath_entry")
b.attach_kprobe(event="vfs_read", fn_name="trace_slowpath_entry")
b.attach_kretprobe(event="__alloc_pages_slowpath", fn_name="trace_slowpath_exit")

# header
print("%-8s %-16s %-6s %-6s %-8s %-5s %-14s" % ("TIME(s)", "COMM", "PID",
    "TID", "FASTPATH", "ORDER", "LAT(ms)"))
#if args.pattern:
#    print("%-1s " % ("P"), end="")
#if args.queue:
#    print("%7s " % ("QUE(ms)"), end="")
#print("%7s" % "LAT(ms)")

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    if event.fastpath == 1:
        fastpath = "true"
    else:
        fastpath = "false"

    #print("%-8s %-16s %-6s %-6s %-6s" % (strftime("%H:%M:%S"), event.task.decode('utf-8', 'replace'), event.pid, event.tid, fastpath))
    print("%-8s %-16s %-6s %-6s %-8s %-5lu %-14.3f" % (strftime("%H:%M:%S"), event.task.decode('utf-8', 'replace'), event.pid, event.tid, fastpath, event.order, float(event.delta_us) / 1000))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

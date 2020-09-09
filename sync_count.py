from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    u64 *count = last.lookup(&key);
    if (count != NULL) {
        *count += 1;
        //last.update(&key, count);
        bpf_trace_printk("%d\\n", *count);
    } else {
        u64 c = 1;
        last.update(&key, &c);
        bpf_trace_printk("%d\\n", c);
    }

    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Counting for sync's... Ctrl-C to end")

# format output
while True:
    (task, pid, _cpu, _flags, ts, ms) = b.trace_fields()
    print("At time %.2f s: sync detected, amount %s ms ago" % (ts, ms))

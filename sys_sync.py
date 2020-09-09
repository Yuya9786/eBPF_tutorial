from bcc import BPF

code = """
int kprobe__sys_sync(void *ctx) { 
    bpf_trace_printk("Hello, World!\\n"); 
    return 0; 
}
"""
b = BPF(text=code)
b.trace_print()

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") event_rb = {
	.type        = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 256 * 1024,
};

struct bpf_map_def SEC("maps") target_family = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 1,
};

// ref /sys/kernel/debug/tracing/events/syscalls/sys_enter_socket/format
struct enter_socket_ctx {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;

	int __syscall_nr;
	u64 family;
	u64 type;
	u64 protocol;
};

struct event {
    u32 pid;
    u8 comm[TASK_COMM_LEN];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct enter_socket_ctx *ctx) {
    int zero = 0;

	int *valp;
    valp = bpf_map_lookup_elem(&target_family, &zero);
	if (!valp) {
        return 0;
	}

	if (ctx->family != *valp) {
        return 0;
    }

    struct event *e;
	e = bpf_ringbuf_reserve(&event_rb, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}
	u64 res;
    u64 id = bpf_get_current_pid_tgid();

	e->pid = (u32)(id >> 32);
    res = bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

	return 0;
}

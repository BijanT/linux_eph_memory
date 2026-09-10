// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault_ops program for testing page read access in WP faults.
 *
 * handle_wp_fault receives a pointer to the faulted page's contents.
 * This program computes a simple checksum of the page and stores it
 * so userspace can verify the BPF program saw the correct data.
 *
 * handle_page_fault fills pages with a caller-controlled pattern so
 * the WP read test can set up known page contents via BPF missing
 * fault handling.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

/* Counters and results readable by userspace */
volatile __u64 wp_fault_count;
volatile __u64 wp_page_checksum;
volatile __u64 wp_page_first_u64;

/* Fill byte for handle_page_fault (set by userspace) */
volatile __u64 fill_byte;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     struct bpf_dynptr *buf)
{
	unsigned char fill = (unsigned char)fill_byte;
	unsigned long size = 4096 << ops_ctx->page_order;

	bpf_dynptr_memset(buf, 0, size, fill);
	return 0;
}

SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     struct bpf_dynptr *buf)
{
	void *p;
	__u64 sum = 0;

	__sync_fetch_and_add(&wp_fault_count, 1);

	/*
	 * WP faults are PTE-granular, so the dynptr always spans one page.
	 * bpf_dynptr_slice()'s length must be a verifier constant.
	 */
	p = bpf_dynptr_slice(buf, 0, NULL, 4096);
	if (!p)
		return 0;

	/* Record first 8 bytes for quick verification */
	wp_page_first_u64 = *((volatile __u64 *)p);

	/* Compute a simple checksum over the whole page */
	for (int i = 0; i < 4096; i++)
		sum += ((__u64)((volatile unsigned char *)p)[i]);

	wp_page_checksum = sum;

	return 0;
}

SEC(".struct_ops.link")
struct fault_ops wp_read_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
	.handle_wp_fault = (void *)handle_wp_fault,
};

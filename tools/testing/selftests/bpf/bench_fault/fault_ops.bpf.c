// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault_ops program for page fault benchmark.
 *
 * Fills each faulted page with a repeating byte pattern,
 * mirroring the userfaultfd benchmark workload.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

/*
 * When false, the handler returns immediately without filling the page.
 * The page stays zeroed (from __GFP_ZERO in folio_alloc).  This is the
 * "read fault" / ZEROPAGE equivalent for bpf_fault.
 */
const volatile __u32 fill_page = 1;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     struct bpf_dynptr *buf)
{
	unsigned char fill = 0x41;
	unsigned long size = 4096 << ops_ctx->page_order;

	if (!fill_page)
		return 0;

	bpf_dynptr_memset(buf, 0, size, fill);
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops bench_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};

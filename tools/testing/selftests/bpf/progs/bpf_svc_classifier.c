// SPDX-License-Identifier: GPL-2.0
/*
 * A svc_classifier for RPC service transports: the peer address is looked
 * up in an LPM trie keyed by {family, address}; a hit returns the class
 * word stored there, a miss returns 0, the anonymous client.  A key of
 * prefixlen 0 is the default for every family, 8 the default for one.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define AF_INET			2
#define AF_INET6		10

#define SVC_CLASSIFIER_NAME_MAX	16

struct svc_xprt___local {
	struct __kernel_sockaddr_storage xpt_remote;
} __attribute__((preserve_access_index));

struct svc_classifier___local {
	char name[SVC_CLASSIFIER_NAME_MAX];
	__u32 (*classify)(const struct svc_xprt___local *xprt);
};

struct prefix_key {
	__u32 prefixlen;	/* 8 (the family byte) + address bits */
	__u8 family;
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct prefix_key);
	__type(value, __u32);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} prefixes SEC(".maps");

__u64 classified;

SEC("struct_ops/classify")
__u32 BPF_PROG(prefix_classify, const struct svc_xprt___local *xprt)
{
	struct __kernel_sockaddr_storage ss;
	struct prefix_key key = {};
	__u32 *class;

	if (bpf_core_read(&ss, sizeof(ss), &xprt->xpt_remote))
		return 0;

	key.family = ss.ss_family;
	switch (ss.ss_family) {
	case AF_INET:
		/* struct sockaddr_in: port at 2, address at 4 */
		__builtin_memcpy(key.addr, &ss.__data[2], 4);
		key.prefixlen = 8 + 32;
		break;
	case AF_INET6:
		/* struct sockaddr_in6: port at 2, flowinfo at 4, address at 8 */
		__builtin_memcpy(key.addr, &ss.__data[6], 16);
		key.prefixlen = 8 + 128;
		break;
	default:
		return 0;
	}

	__sync_fetch_and_add(&classified, 1);
	class = bpf_map_lookup_elem(&prefixes, &key);
	return class ? *class : 0;
}

SEC(".struct_ops.link")
struct svc_classifier___local prefix = {
	.name		= "prefix",
	.classify	= (void *)prefix_classify,
};

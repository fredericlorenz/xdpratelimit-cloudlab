// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "ratelimit.h"

#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define GCRA_CAS_RETRIES 8

// The ELF default is the vulnerable organization studied by the PoC. The
// userspace loader may override the type and flags before creating the map.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 1024); // Userspace may override before map creation
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
	__type(key, struct rl_key);
	__type(value, struct rl_entry);
} rl_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rl_config);
} rl_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rl_stats);
} rl_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_QUEUES);
	__type(key, __u32);
	__type(value, struct rl_stats);
} rl_queue_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rl_target_stats);
} rl_target_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TARGET_EVENTS);
	__type(key, __u32);
	__type(value, struct rl_target_event);
} rl_events SEC(".maps");

struct l4_ports {
	__be16 source;
	__be16 dest;
};

enum parse_result {
	PARSE_OK = 0,
	PARSE_BYPASS = 1,
};

enum limit_result {
	LIMIT_PASS = 0,
	LIMIT_RATE_DROP,
	LIMIT_CONTENTION_DROP,
};

static __always_inline void stats_rx(struct rl_stats *global, struct rl_stats *queue) {
	if (global)
		global->rx++;
	if (queue)
		queue->rx++;
}

#define STATS_INC(global, queue, field) do { \
	if (global)                              \
		(global)->field++;                   \
	if (queue)                               \
		(queue)->field++;                    \
} while (0)

static __always_inline int parse_key(struct xdp_md *ctx, __u32 key_mode, struct rl_key *key) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 ihl_len;

	if ((void *)(eth + 1) > data_end)
		return PARSE_BYPASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return PARSE_BYPASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
		return PARSE_BYPASS;

	ihl_len = (__u32)ip->ihl * 4;
	if ((void *)ip + ihl_len > data_end)
		return PARSE_BYPASS;

	key->saddr = ip->saddr;
	if (key_mode == KEY_SADDR)
		return PARSE_OK;

	key->daddr = ip->daddr;
	key->proto = ip->protocol;

	// Non-initial fragments do not contain transport-layer ports
	if (bpf_ntohs(ip->frag_off) & IPV4_FRAGMENT_OFFSET_MASK)
		return PARSE_BYPASS;

	if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
		struct l4_ports *ports = (void *)ip + ihl_len;

		if ((void *)(ports + 1) > data_end)
			return PARSE_BYPASS;
		key->sport = ports->source;
		key->dport = ports->dest;
	}

	return PARSE_OK;
}

static __always_inline int initialize_entry(const struct rl_key *key,
					    struct rl_entry **entry_out,
					    __u64 now, __u64 interval_ns,
					    struct rl_stats *global,
					    struct rl_stats *queue,
					    int *inserted_out) {
	struct rl_entry initial = {
		.tat = now + interval_ns,
		.created_ns = now,
		.passed = 1,
	};
	struct rl_entry *entry = *entry_out;
	*inserted_out = 0;

	if (entry) {
		// A key can exist while this CPU's per-CPU value is untouched
		*entry = initial;
		STATS_INC(global, queue, new_entries);
		return XDP_PASS;
	}

	if (bpf_map_update_elem(&rl_state, key, &initial, BPF_NOEXIST) == 0) {
		*inserted_out = 1;
		STATS_INC(global, queue, new_entries);
		STATS_INC(global, queue, map_inserts);
		return XDP_PASS;
	}

	// Another CPU may have installed the global key between lookup/update
	STATS_INC(global, queue, insert_fail);
	entry = bpf_map_lookup_elem(&rl_state, key);
	if (entry && entry->created_ns == 0) {
		*entry = initial;
		STATS_INC(global, queue, new_entries);
		return XDP_PASS;
	}

	*entry_out = entry;
	return -1;
}

static __always_inline struct rl_target_stats *target_stats(const struct rl_config *config, 
						const struct rl_key *key) {
	const __u32 zero = 0;

	if (!config->target_enabled || key->saddr != config->target_saddr)
		return NULL;
	return bpf_map_lookup_elem(&rl_target_stats, &zero);
}

static __always_inline void record_target_initialization(struct rl_target_stats *target,
						 __u64 now, __u32 queue_id, int inserted) {
	__u32 cpu;

	if (!target)
		return;
	cpu = bpf_get_smp_processor_id();
	if (__sync_val_compare_and_swap(&target->first_created_ns, 0, now) == 0) {
		target->first_cpu = cpu;
		target->first_queue = queue_id;
	}
	target->latest_created_ns = now;
	target->latest_cpu = cpu;
	target->latest_queue = queue_id;
	__sync_fetch_and_add(&target->initializations, 1);
	if (inserted)
		__sync_fetch_and_add(&target->map_insertions, 1);
}

static __always_inline void record_target_result(struct rl_target_stats *target,
						 enum limit_result result) {
	if (!target)
		return;
	if (result == LIMIT_PASS)
		__sync_fetch_and_add(&target->passed, 1);
	else
		__sync_fetch_and_add(&target->dropped, 1);
}

static __always_inline enum limit_result apply_gcra(struct rl_entry *entry,
						   const struct rl_config *config,
						   __u64 now, __u64 *prior_tat) {
#pragma unroll
	for (int attempt = 0; attempt < GCRA_CAS_RETRIES; attempt++) {
		__u64 tat = entry->tat;
		__u64 allow_at = tat > config->tolerance_ns ? tat - config->tolerance_ns : 0;
		__u64 next_tat;
		*prior_tat = tat;

		if (now < allow_at) {
			__sync_fetch_and_add(&entry->dropped, 1);
			return LIMIT_RATE_DROP;
		}

		next_tat = (tat > now ? tat : now) + config->interval_ns;
		if (__sync_val_compare_and_swap(&entry->tat, tat, next_tat) == tat) {
			__sync_fetch_and_add(&entry->passed, 1);
			return LIMIT_PASS;
		}
	}

	return LIMIT_CONTENTION_DROP;
}

static __always_inline void record_target_event(struct rl_target_stats *target,
		__u64 now, __u64 prior_tat, __u64 created, __u32 queue,
		__u32 action, int inserted) {
	if (!target)
		return;
	__u64 index = __sync_fetch_and_add(&target->event_count, 1);
	if (index >= MAX_TARGET_EVENTS) {
		__sync_fetch_and_add(&target->event_overflow, 1);
		return;
	}
	__u32 slot = index;
	struct rl_target_event *event = bpf_map_lookup_elem(&rl_events, &slot);
	if (event) {
		event->observed_ns = now;
		event->prior_tat_ns = prior_tat;
		event->created_ns = created;
		event->cpu = bpf_get_smp_processor_id();
		event->queue = queue;
		event->action = action;
		event->inserted = inserted;
	}
}

SEC("xdp")
int xdp_ratelimit(struct xdp_md *ctx) {
	const __u32 zero = 0;
	__u32 queue_id = ctx->rx_queue_index;
	struct rl_stats *global = bpf_map_lookup_elem(&rl_stats, &zero);
	struct rl_stats *queue = NULL;
	struct rl_config *config;
	struct rl_entry *entry;
	struct rl_target_stats *target;
	struct rl_key key = {};
	__u64 now;
	__u64 prior_tat = 0;
	int inserted = 0;
	int result;

	if (queue_id < MAX_QUEUES)
		queue = bpf_map_lookup_elem(&rl_queue_stats, &queue_id);
	stats_rx(global, queue);

	config = bpf_map_lookup_elem(&rl_config, &zero);
	if (!config || config->interval_ns == 0 || config->key_mode > KEY_FLOW) {
		STATS_INC(global, queue, bypassed);
		return XDP_PASS;
	}

	if (parse_key(ctx, config->key_mode, &key) != PARSE_OK) {
		STATS_INC(global, queue, bypassed);
		return XDP_PASS;
	}

	target = target_stats(config, &key);
	now = bpf_ktime_get_ns();
	entry = bpf_map_lookup_elem(&rl_state, &key);
	if (!entry || entry->created_ns == 0) {
		result = initialize_entry(&key, &entry, now, config->interval_ns,
					  global, queue, &inserted);
		if (result >= 0) {
			record_target_event(target, now, 0, now, queue_id,
					    RL_AUDIT_INITIALIZE, inserted);
			record_target_initialization(target, now, queue_id, inserted);
			record_target_result(target, LIMIT_PASS);
			STATS_INC(global, queue, passed);
			return result;
		}
		if (!entry) {
			record_target_event(target, now, 0, 0, queue_id,
					    RL_AUDIT_INSERT_FAIL, 0);
			record_target_result(target, LIMIT_RATE_DROP);
			STATS_INC(global, queue, dropped);
			return XDP_DROP;
		}
	}

	result = apply_gcra(entry, config, now, &prior_tat);
	record_target_event(target, now, prior_tat, entry->created_ns, queue_id, result, 0);
	if (result == LIMIT_PASS) {
		record_target_result(target, LIMIT_PASS);
		STATS_INC(global, queue, passed);
		return XDP_PASS;
	}
	if (result == LIMIT_CONTENTION_DROP)
		STATS_INC(global, queue, contention_drop);
	record_target_result(target, result);
	STATS_INC(global, queue, dropped);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
// Types shared between the XDP program and the userspace loader
#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <linux/types.h>

#define MAX_QUEUES 64
#define MAX_TARGET_EVENTS 256
#define RL_NSEC_PER_SEC 1000000000ULL

enum key_mode {
	KEY_SADDR = 0, // One bucket per IPv4 source address
	KEY_FLOW  = 1, // One bucket per (saddr, daddr, proto, sport, dport)
};

enum rl_map_mode {
	RL_MAP_SHARED_GLOBAL = 0,
	RL_MAP_SHARED_LOCAL,
	RL_MAP_PERCPU_GLOBAL,
	RL_MAP_PERCPU_LOCAL,
	RL_MAP_HASH_SHARED,
	RL_MAP_HASH_PERCPU,
};

// Fixed 16-byte key, fields not used by the active key mode stay zero
struct rl_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8   proto;
	__u8   pad[3];
};

// Per-key state stored in the configured state map
struct rl_entry {
	__u64 tat;        // GCRA theoretical arrival time (ns, CLOCK_MONOTONIC)
	__u64 created_ns; // Changes when this entry is evicted and reinserted
	__u64 passed;
	__u64 dropped;
};

// Written by userspace before the XDP program is attached
struct rl_config {
	__u64 interval_ns;  // Spacing between packets at the configured rate
	__u64 tolerance_ns; // (burst - 1) * interval_ns
	__u32 rate_pps;
	__u32 burst;
	__u32 key_mode;
	__u32 map_mode;
	__be32 target_saddr; // Optional source monitored independently of rl_state
	__u32 target_enabled;
	__u64 trial_id; // Explicit identity shared with the sender summary
};

// Persists independently of rl_state so target eviction does not erase evidence
struct rl_target_stats {
	__u64 first_created_ns;
	__u64 latest_created_ns;
	__u64 initializations;
	__u64 map_insertions;
	__u64 passed;
	__u64 dropped;
	__u32 first_cpu;
	__u32 latest_cpu;
	__u32 first_queue;
	__u32 latest_queue;
	__u64 event_count;
	__u64 event_overflow;
};

enum rl_audit_action {
	RL_AUDIT_PASS = 0,
	RL_AUDIT_RATE_DROP = 1,
	RL_AUDIT_CONTENTION_DROP = 2,
	RL_AUDIT_INITIALIZE = 3,
	RL_AUDIT_INSERT_FAIL = 4,
};

// Bounded, non-evicting packet evidence. Read only after traffic has stopped.
struct rl_target_event {
	__u64 observed_ns;
	__u64 prior_tat_ns; // Exact GCRA TAT on a rate drop; before update on a pass
	__u64 created_ns;
	__u32 cpu;
	__u32 queue;
	__u32 action;
	__u32 inserted;
};

// Counters are kept per CPU, rl_queue_stats also indexes them by RX queue
struct rl_stats {
	__u64 rx;          // Every packet seen by the program
	__u64 bypassed;    // Non-IPv4, malformed or unkeyable packets
	__u64 passed;
	__u64 dropped;
	__u64 new_entries; // Newly initialized CPU-local rate buckets
	__u64 map_inserts; // Successful new-key inserts into rl_state
	__u64 insert_fail; // Failed BPF_NOEXIST inserts (race or full non-LRU map)
	__u64 contention_drop; // CAS retry limit reached in a shared-value mode
};

#endif // RATELIMIT_H

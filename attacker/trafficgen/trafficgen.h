// SPDX-License-Identifier: GPL-2.0
#ifndef TRAFFICGEN_H
#define TRAFFICGEN_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define RSS_KEY_LEN 128 // Maximum supported key length; four-tuple hashing uses 16 bytes
#define RSS_INDIR_MAX 4096
#define MAX_PACKET_LEN 128
#define TG_QUEUE_UNKNOWN UINT32_MAX

enum tg_key_mode {
	TG_KEY_SOURCE = 0, // Vary saddr, steer with sport
	TG_KEY_FLOW   = 1, // Fixed saddr, vary (sport, dport)
};

enum tg_proto {
	TG_PROTO_UDP = IPPROTO_UDP,
	TG_PROTO_TCP = IPPROTO_TCP,
};

enum rss_input_transform {
	RSS_XFRM_NONE = 0,
	RSS_XFRM_SYMMETRIC_OR_XOR,
};

struct rss_config {
	uint8_t key[RSS_KEY_LEN];
	uint32_t indir[RSS_INDIR_MAX];
	size_t indir_len;
	enum rss_input_transform input_transform;
	int loaded;
};

struct flow_tuple {
	uint32_t saddr_be;
	uint32_t daddr_be;
	uint16_t sport_be;
	uint16_t dport_be;
	uint8_t  proto;
	uint32_t predicted_queue;
};

struct tg_options {
	const char *ifname;
	const char *rss_file;
	const char *profile_name;
	uint32_t src_ip_be;      // Base source IP (eg. 10.77.0.2)
	uint32_t dst_ip_be;      // Victim IP (eg. 10.77.0.1)
	uint16_t base_sport;     // Used by 'probe' profile
	uint16_t base_dport;     // Destination port
	enum tg_key_mode key_mode;
	enum tg_proto proto;
	int target_queue;        // 0..N-1 for steered, -1 for any
	uint32_t num_keys;       // Number of unique keys (K)
	uint32_t pkts_per_key;   // Packets sent per key (1 vs 2+)
	uint32_t rate_pps;       // 0 = unthrottled burst, >0 = paced pps
	uint32_t warmup_pkts;    // Target packets sent before eviction traffic
	uint32_t retry_pkts;     // Target packets sent after eviction traffic
	uint32_t deadline_ms;    // Maximum warmup-to-retry duration for attack mode
	const char *summary_file; // Optional JSON result path for attack mode
	int dry_run;             // Print generated tuples & queues without sending
	uint64_t trial_id;        // Identity of the fresh victim attachment
	const char *chaff_profile; // attack chaff generator: steered or random
};

struct attack_result {
	uint32_t target_queue;
	size_t warmup_intended;
	size_t warmup_sent;
	size_t chaff_intended;
	size_t chaff_sent;
	size_t retry_intended;
	size_t retry_sent;
	uint64_t start_ns;
	uint64_t warmup_end_ns;
	uint64_t chaff_end_ns;
	uint64_t retry_end_ns;
	uint64_t deadline_ns;
	int within_deadline;
};

// Pluggable Traffic Profile Interface
struct traffic_profile {
	const char *name;
	const char *description;
	int (*generate_tuples)(const struct tg_options *opts,
			       const struct rss_config *rss,
			       struct flow_tuple *out_tuples);
};

// rss.c
int rss_load_file(const char *path, struct rss_config *rss);
uint32_t rss_toeplitz_hash(uint32_t saddr_be, uint32_t daddr_be,
			   uint16_t sport_be, uint16_t dport_be,
			   const uint8_t *key);
uint32_t rss_predict_queue(const struct rss_config *rss,
			   uint32_t saddr_be, uint32_t daddr_be,
			   uint16_t sport_be, uint16_t dport_be);
int rss_has_queue(const struct rss_config *rss, uint32_t queue);

// profiles.c
const struct traffic_profile *find_profile(const char *name);
void list_profiles(void);

// net_tx.c
int net_transmit_workload(const struct tg_options *opts,
			  const struct flow_tuple *tuples,
			  size_t num_tuples);
int net_transmit_attack(const struct tg_options *opts,
			const struct flow_tuple *target,
			const struct flow_tuple *chaff,
			size_t num_chaff,
			struct attack_result *result);

#endif

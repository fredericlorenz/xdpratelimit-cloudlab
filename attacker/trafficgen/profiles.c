// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trafficgen.h"

#define MAX_STEERING_ATTEMPTS 100000000ULL

// Deterministic sequence of disposable addresses beginning at 10.100.0.1
static uint32_t candidate_saddr_be(uint32_t index) {
	uint32_t base = (10u << 24) | (100u << 16);
	uint32_t ip_host_order = base + index + 1;
	return htonl(ip_host_order);
}

// Probe profile: single deterministic flow (used for blocked client warmup & bypass check)
static int gen_probe(const struct tg_options *opts,
		     const struct rss_config *rss,
		     struct flow_tuple *out) {
	for (uint32_t i = 0; i < opts->num_keys; i++) {
		uint16_t sport_be = htons(opts->base_sport + i);
		uint16_t dport_be = htons(opts->base_dport);
		out[i] = (struct flow_tuple){
			.saddr_be = opts->src_ip_be,
			.daddr_be = opts->dst_ip_be,
			.sport_be = sport_be,
			.dport_be = dport_be,
			.proto    = (uint8_t)opts->proto,
			.predicted_queue = rss->loaded ?
				rss_predict_queue(rss, opts->src_ip_be, opts->dst_ip_be,
						  sport_be, dport_be) : TG_QUEUE_UNKNOWN,
		};
	}
	return 0;
}

// Random profile: unsteered disposable keys distributed across all queues
static int gen_random(const struct tg_options *opts,
		      const struct rss_config *rss,
		      struct flow_tuple *out) {
	uint32_t source_cursor = 0;

	for (uint32_t i = 0; i < opts->num_keys; i++) {
		uint32_t saddr_be = opts->src_ip_be;
		uint16_t sport_be = htons(10000 + (i % 50000));
		uint16_t dport_be = htons(opts->base_dport + (i / 50000));

		if (opts->key_mode == TG_KEY_SOURCE) {
			do {
				saddr_be = candidate_saddr_be(source_cursor++);
			} while (saddr_be == opts->src_ip_be || saddr_be == opts->dst_ip_be);
		}
		out[i] = (struct flow_tuple){
			.saddr_be = saddr_be,
			.daddr_be = opts->dst_ip_be,
			.sport_be = sport_be,
			.dport_be = dport_be,
			.proto    = (uint8_t)opts->proto,
			.predicted_queue = rss->loaded ?
				rss_predict_queue(rss, saddr_be, opts->dst_ip_be,
						  sport_be, dport_be) : TG_QUEUE_UNKNOWN,
		};
	}
	return 0;
}

// Steered profile: disposable keys filtered via Toeplitz hash to hit target_queue
static int gen_steered(const struct tg_options *opts,
		       const struct rss_config *rss,
		       struct flow_tuple *out) {
	if (!rss->loaded || opts->target_queue < 0) {
		fprintf(stderr, "'steered' profile requires --rss-file and --target-queue\n");
		return -1;
	}
	if (!rss_has_queue(rss, (uint32_t)opts->target_queue)) {
		fprintf(stderr, "Target queue %d is absent from the RSS indirection table\n",
			opts->target_queue);
		return -1;
	}

	uint32_t found = 0;
	uint32_t cursor = 0;
	uint16_t dport_be = htons(opts->base_dport);
	uint64_t attempts = 0;

	while (found < opts->num_keys) {
		if (attempts >= MAX_STEERING_ATTEMPTS) {
			fprintf(stderr, "Could not find %u tuples for queue %d after %llu attempts\n",
				found, opts->target_queue, (unsigned long long)attempts);
			return -1;
		}
		if (opts->key_mode == TG_KEY_SOURCE) {
			// Distinct saddr per key; solve for a sport that hashes to target_queue
			uint32_t saddr_be;

			do {
				saddr_be = candidate_saddr_be(cursor++);
			} while (saddr_be == opts->src_ip_be || saddr_be == opts->dst_ip_be);
			for (uint32_t p = 1024; p < 65535; p++) {
				attempts++;
				uint16_t sport_be = htons((uint16_t)p);
				uint32_t q = rss_predict_queue(rss, saddr_be, opts->dst_ip_be,
							       sport_be, dport_be);
				if ((int)q == opts->target_queue) {
					out[found++] = (struct flow_tuple){
						.saddr_be = saddr_be,
						.daddr_be = opts->dst_ip_be,
						.sport_be = sport_be,
						.dport_be = dport_be,
						.proto    = (uint8_t)opts->proto,
						.predicted_queue = q,
					};
					break;
				}
			}
		} else {
			// TG_KEY_FLOW: Fixed saddr, find distinct (sport, dport) pairs on target_queue
			uint16_t sport_be = htons(1024 + (cursor % 60000));
			uint16_t cur_dport_be = htons(opts->base_dport + (cursor / 60000));
			cursor++;
			attempts++;
			uint32_t q = rss_predict_queue(rss, opts->src_ip_be, opts->dst_ip_be,
						       sport_be, cur_dport_be);
			if ((int)q == opts->target_queue) {
				out[found++] = (struct flow_tuple){
					.saddr_be = opts->src_ip_be,
					.daddr_be = opts->dst_ip_be,
					.sport_be = sport_be,
					.dport_be = cur_dport_be,
					.proto    = (uint8_t)opts->proto,
					.predicted_queue = q,
				};
			}
		}
	}
	return 0;
}

// Collateral profile: generates background keys in 10.200.x.y to measure collateral eviction
static int gen_collateral(const struct tg_options *opts,
			  const struct rss_config *rss,
			  struct flow_tuple *out) {
	uint32_t found = 0;
	uint32_t cursor = 1;
	uint16_t dport_be = htons(opts->base_dport);
	uint64_t attempts = 0;

	if (opts->target_queue >= 0) {
		if (!rss->loaded) {
			fprintf(stderr, "Targeted collateral traffic requires --rss-file\n");
			return -1;
		}
		if (!rss_has_queue(rss, (uint32_t)opts->target_queue)) {
			fprintf(stderr, "Target queue %d is absent from the RSS indirection table\n",
				opts->target_queue);
			return -1;
		}
	}

	while (found < opts->num_keys) {
		if (attempts++ >= MAX_STEERING_ATTEMPTS) {
			fprintf(stderr, "Could not generate requested collateral tuples\n");
			return -1;
		}
		uint32_t saddr_be = htonl((10u << 24) | (200u << 16) | (cursor & 0xffffu));
		uint16_t sport_be = htons(20000 + (cursor % 40000));
		cursor++;

		uint32_t q = rss->loaded ?
			rss_predict_queue(rss, saddr_be, opts->dst_ip_be,
					  sport_be, dport_be) : TG_QUEUE_UNKNOWN;

		if (opts->target_queue >= 0 && (int)q != opts->target_queue)
			continue;

		out[found++] = (struct flow_tuple){
			.saddr_be = saddr_be,
			.daddr_be = opts->dst_ip_be,
			.sport_be = sport_be,
			.dport_be = dport_be,
			.proto    = (uint8_t)opts->proto,
			.predicted_queue = q,
		};
	}
	return 0;
}

static const struct traffic_profile profiles[] = {
	{ "probe", "Deterministic client flow(s) for warmup and allowance-reset checks",
	  gen_probe },
	{ "random", "Unsteered disposable keys across all RX queues (control baseline)",
	  gen_random },
	{ "steered", "RSS-steered disposable keys targeting a specific RX queue",
	  gen_steered },
	{ "attack", "Timed target warmup, RSS-steered eviction traffic, and retry",
	  gen_steered },
	{ "collateral", "Background flows (10.200.0.0/16) to measure collateral eviction",
	  gen_collateral },
};

const struct traffic_profile *find_profile(const char *name) {
	for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		if (strcmp(name, profiles[i].name) == 0)
			return &profiles[i];
	}
	return NULL;
}

void list_profiles(void) {
	fprintf(stderr, "Available traffic profiles:\n");
	for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++)
		fprintf(stderr, "  %-12s %s\n", profiles[i].name, profiles[i].description);
}

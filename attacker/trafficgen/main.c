// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trafficgen.h"

#define MAX_SOURCE_KEYS 10223615U

static void usage(const char *program) {
	fprintf(stderr,
		"Usage: %s --interface IFACE --profile PROFILE [OPTIONS]\n\n"
		"Options:\n"
		"  -i, --interface IFACE     Experiment interface (required unless dry-run)\n"
		"  -d, --dst IP              Victim IPv4 address (default: 10.77.0.1)\n"
		"  -s, --src IP              Target source address (default: 10.77.0.2)\n"
		"  -P, --profile NAME        probe, random, steered, attack, collateral\n"
		"  -k, --key source|flow     Map key dimension to vary (default: source)\n"
		"  -p, --proto udp|tcp       Transport protocol (default: udp)\n"
		"  -q, --target-queue QUEUE  Queue for steered traffic; attack auto-detects\n"
		"  -n, --keys COUNT          Number of disposable keys (default: 256)\n"
		"  -c, --pkts-per-key COUNT  Chaff packets per key (default: 1)\n"
		"  -r, --rate PPS            0 for unthrottled, otherwise 1..1e9 pps\n"
		"  -x, --rss-file PATH       rss.conf generated from the victim\n"
		"      --sport PORT          Target source port (default: 50000)\n"
		"      --dport PORT          Destination port (default: 1234)\n"
		"      --warmup-pkts COUNT   Target packets before chaff (default: 11)\n"
		"      --retry-pkts COUNT    Target packets after chaff (default: 1)\n"
		"      --deadline-ms MS      Attack recovery deadline (default: 900)\n"
		"      --summary PATH        Write attack phase results as JSON\n"
		"      --trial-id ID         Identity shared with fresh victim attachment\n"
		"      --chaff PROFILE       Attack chaff: steered or random (default: steered)\n"
		"      --dry-run             Print tuples and predicted queues only\n"
		"  -h, --help                Show this help\n\n",
		program);
	list_profiles();
}

static int parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
		     uint32_t *value) {
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end != '\0' || parsed < minimum || parsed > maximum)
		return -1;
	*value = (uint32_t)parsed;
	return 0;
}

static int parse_port(const char *text, uint16_t *port) {
	uint32_t parsed;

	if (parse_u32(text, 1, UINT16_MAX, &parsed) != 0)
		return -1;
	*port = (uint16_t)parsed;
	return 0;
}

static int parse_ipv4(const char *text, uint32_t *address_be) {
	struct in_addr address;

	if (inet_pton(AF_INET, text, &address) != 1)
		return -1;
	*address_be = address.s_addr;
	return 0;
}

static int parse_options(int argc, char **argv, struct tg_options *opts) {
	static const struct option long_options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "dst", required_argument, NULL, 'd' },
		{ "src", required_argument, NULL, 's' },
		{ "profile", required_argument, NULL, 'P' },
		{ "key", required_argument, NULL, 'k' },
		{ "proto", required_argument, NULL, 'p' },
		{ "target-queue", required_argument, NULL, 'q' },
		{ "keys", required_argument, NULL, 'n' },
		{ "pkts-per-key", required_argument, NULL, 'c' },
		{ "rate", required_argument, NULL, 'r' },
		{ "rss-file", required_argument, NULL, 'x' },
		{ "sport", required_argument, NULL, 1000 },
		{ "dport", required_argument, NULL, 1001 },
		{ "warmup-pkts", required_argument, NULL, 1002 },
		{ "retry-pkts", required_argument, NULL, 1003 },
		{ "deadline-ms", required_argument, NULL, 1004 },
		{ "summary", required_argument, NULL, 1005 },
		{ "dry-run", no_argument, NULL, 1006 },
		{ "trial-id", required_argument, NULL, 1007 },
		{ "chaff", required_argument, NULL, 1008 },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "i:d:s:P:k:p:q:n:c:r:x:h",
				     long_options, NULL)) != -1) {
		switch (option) {
		case 'i':
			opts->ifname = optarg;
			break;
		case 'd':
			if (parse_ipv4(optarg, &opts->dst_ip_be) != 0)
				return -1;
			break;
		case 's':
			if (parse_ipv4(optarg, &opts->src_ip_be) != 0)
				return -1;
			break;
		case 'P':
			opts->profile_name = optarg;
			break;
		case 'k':
			if (strcmp(optarg, "source") == 0)
				opts->key_mode = TG_KEY_SOURCE;
			else if (strcmp(optarg, "flow") == 0)
				opts->key_mode = TG_KEY_FLOW;
			else
				return -1;
			break;
		case 'p':
			if (strcmp(optarg, "udp") == 0)
				opts->proto = TG_PROTO_UDP;
			else if (strcmp(optarg, "tcp") == 0)
				opts->proto = TG_PROTO_TCP;
			else
				return -1;
			break;
		case 'q': {
			uint32_t queue;

			if (parse_u32(optarg, 0, INT_MAX, &queue) != 0)
				return -1;
			opts->target_queue = (int)queue;
			break;
		}
		case 'n':
			if (parse_u32(optarg, 1, UINT32_MAX, &opts->num_keys) != 0)
				return -1;
			break;
		case 'c':
			if (parse_u32(optarg, 1, UINT32_MAX, &opts->pkts_per_key) != 0)
				return -1;
			break;
		case 'r':
			if (parse_u32(optarg, 0, 1000000000U, &opts->rate_pps) != 0)
				return -1;
			break;
		case 'x':
			opts->rss_file = optarg;
			break;
		case 1000:
			if (parse_port(optarg, &opts->base_sport) != 0)
				return -1;
			break;
		case 1001:
			if (parse_port(optarg, &opts->base_dport) != 0)
				return -1;
			break;
		case 1002:
			if (parse_u32(optarg, 1, UINT32_MAX, &opts->warmup_pkts) != 0)
				return -1;
			break;
		case 1003:
			if (parse_u32(optarg, 1, UINT32_MAX, &opts->retry_pkts) != 0)
				return -1;
			break;
		case 1004:
			if (parse_u32(optarg, 1, UINT32_MAX, &opts->deadline_ms) != 0)
				return -1;
			break;
		case 1005:
			opts->summary_file = optarg;
			break;
		case 1006:
			opts->dry_run = 1;
			break;
		case 1007: {
			char *end;
			errno = 0;
			opts->trial_id = strtoull(optarg, &end, 10);
			if (errno || !*optarg || *end || *optarg == '-' || !opts->trial_id)
				return -1;
			break;
		}
		case 1008:
			if (strcmp(optarg, "steered") != 0 && strcmp(optarg, "random") != 0)
				return -1;
			opts->chaff_profile = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			return -1;
		}
	}
	if (optind != argc || (!opts->dry_run && !opts->ifname))
		return -1;
	if (opts->key_mode == TG_KEY_SOURCE && opts->num_keys > MAX_SOURCE_KEYS)
		return -1;
	return 0;
}

static void print_tuple(uint32_t index, const struct flow_tuple *tuple) {
	char source[INET_ADDRSTRLEN];
	char destination[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &tuple->saddr_be, source, sizeof(source));
	inet_ntop(AF_INET, &tuple->daddr_be, destination, sizeof(destination));
	if (tuple->predicted_queue == TG_QUEUE_UNKNOWN) {
		printf("[%u] %s:%u -> %s:%u proto=%u predicted_queue=unknown\n",
		       index, source, ntohs(tuple->sport_be), destination,
		       ntohs(tuple->dport_be), tuple->proto);
	} else {
		printf("[%u] %s:%u -> %s:%u proto=%u predicted_queue=%u\n",
		       index, source, ntohs(tuple->sport_be), destination,
		       ntohs(tuple->dport_be), tuple->proto, tuple->predicted_queue);
	}
}

static struct flow_tuple target_tuple(const struct tg_options *opts,
				      const struct rss_config *rss) {
	struct flow_tuple target = {
		.saddr_be = opts->src_ip_be,
		.daddr_be = opts->dst_ip_be,
		.sport_be = htons(opts->base_sport),
		.dport_be = htons(opts->base_dport),
		.proto = (uint8_t)opts->proto,
		.predicted_queue = TG_QUEUE_UNKNOWN,
	};

	if (rss->loaded) {
		target.predicted_queue = rss_predict_queue(rss, target.saddr_be, target.daddr_be,
							  target.sport_be, target.dport_be);
	}
	return target;
}

static int write_attack_summary(const struct tg_options *opts, const struct attack_result *result) {
	const char *path = opts->summary_file;
	char source[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &opts->src_ip_be, source, sizeof(source));
	FILE *output = stdout;
	uint64_t duration_ns = result->retry_end_ns >= result->start_ns ?
		result->retry_end_ns - result->start_ns : 0;
	uint64_t eviction_window_ns = result->retry_end_ns >= result->warmup_end_ns ?
		result->retry_end_ns - result->warmup_end_ns : 0;

	if (path) {
		output = fopen(path, "wx");
		if (!output) {
			perror("fopen attack summary");
			return -1;
		}
	}
	fprintf(output,
		"{\"schema_version\":2,\"trial_id\":%llu,\"target_source\":\"%s\","
		"\"chaff_profile\":\"%s\","
		"\"target_queue\":%u,\"warmup_intended\":%zu,\"warmup_sent\":%zu,"
		"\"chaff_intended\":%zu,\"chaff_sent\":%zu,\"retry_intended\":%zu,"
		"\"retry_sent\":%zu,\"start_ns\":%llu,\"warmup_end_ns\":%llu,"
		"\"chaff_end_ns\":%llu,\"retry_end_ns\":%llu,\"duration_ns\":%llu,"
		"\"eviction_window_ns\":%llu,\"deadline_ns\":%llu,"
		"\"within_deadline\":%s}\n",
		(unsigned long long)opts->trial_id, source,
		opts->chaff_profile,
		result->target_queue, result->warmup_intended, result->warmup_sent,
		result->chaff_intended, result->chaff_sent, 
		result->retry_intended, result->retry_sent, 
		(unsigned long long)result->start_ns,
		(unsigned long long)result->warmup_end_ns,
		(unsigned long long)result->chaff_end_ns,
		(unsigned long long)result->retry_end_ns, 
		(unsigned long long)duration_ns,
		(unsigned long long)eviction_window_ns,
		(unsigned long long)result->deadline_ns,
		result->within_deadline ? "true" : "false");
	if (path && fclose(output) != 0) {
		perror("fclose attack summary");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {
	struct tg_options opts = {
		.profile_name = "probe",
		.src_ip_be = 0,
		.dst_ip_be = 0,
		.base_sport = 50000,
		.base_dport = 1234,
		.key_mode = TG_KEY_SOURCE,
		.proto = TG_PROTO_UDP,
		.target_queue = -1,
		.num_keys = 256,
		.pkts_per_key = 1,
		.rate_pps = 0,
		.warmup_pkts = 11,
		.retry_pkts = 1,
		.deadline_ms = 900,
		.chaff_profile = "steered",
	};
	const struct traffic_profile *profile;
	const struct traffic_profile *chaff_profile;
	struct rss_config rss = {};
	struct flow_tuple *tuples = NULL;
	struct flow_tuple target;
	int is_attack = 0;
	int result;

	parse_ipv4("10.77.0.2", &opts.src_ip_be);
	parse_ipv4("10.77.0.1", &opts.dst_ip_be);
	if (parse_options(argc, argv, &opts) != 0) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	profile = find_profile(opts.profile_name);
	if (!profile) {
		fprintf(stderr, "Unknown profile: %s\n", opts.profile_name);
		list_profiles();
		return EXIT_FAILURE;
	}
	is_attack = strcmp(opts.profile_name, "attack") == 0;
	chaff_profile = profile;
	if (is_attack) {
		chaff_profile = find_profile(opts.chaff_profile);
		if (!chaff_profile) {
			fprintf(stderr, "Unknown attack chaff profile: %s\n", opts.chaff_profile);
			return EXIT_FAILURE;
		}
	}
	if (opts.rss_file && rss_load_file(opts.rss_file, &rss) < 0)
		return EXIT_FAILURE;

	target = target_tuple(&opts, &rss);
	if (is_attack) {
		if (!opts.trial_id) {
			fprintf(stderr, "Attack profile requires --trial-id from the victim attachment\n");
			return EXIT_FAILURE;
		}
		if (opts.key_mode != TG_KEY_SOURCE) {
			fprintf(stderr,
				"Attack profile currently requires --key source for target auditing\n");
			return EXIT_FAILURE;
		}
		if (!rss.loaded || target.predicted_queue == TG_QUEUE_UNKNOWN) {
			fprintf(stderr, "Attack profile requires a valid --rss-file\n");
			return EXIT_FAILURE;
		}
		if (opts.target_queue >= 0 &&
		    (uint32_t)opts.target_queue != target.predicted_queue) {
			fprintf(stderr,
				"Target tuple maps to queue %u, not requested queue %d\n",
				target.predicted_queue, opts.target_queue);
			return EXIT_FAILURE;
		}
		opts.target_queue = (int)target.predicted_queue;
	}

	tuples = calloc(opts.num_keys, sizeof(*tuples));
	if (!tuples) {
		perror("calloc tuples");
		return EXIT_FAILURE;
	}
	if ((is_attack ? chaff_profile : profile)->generate_tuples(&opts, &rss, tuples) < 0) {
		free(tuples);
		return EXIT_FAILURE;
	}

	if (opts.dry_run) {
		if (is_attack) {
			printf("target:\n");
			print_tuple(0, &target);
			printf("chaff:\n");
		}
		for (uint32_t i = 0; i < opts.num_keys; i++)
			print_tuple(i, &tuples[i]);
		free(tuples);
		return EXIT_SUCCESS;
	}

	if (is_attack) {
		struct attack_result attack_result;

		result = net_transmit_attack(&opts, &target, tuples, opts.num_keys,
					     &attack_result);
		if (write_attack_summary(&opts, &attack_result) != 0)
			result = -1;
	} else {
		result = net_transmit_workload(&opts, tuples, opts.num_keys);
	}
	free(tuples);
	return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

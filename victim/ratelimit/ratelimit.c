// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ratelimit.h"

struct map_mode_spec {
	enum rl_map_mode id;
	const char *name;
	enum bpf_map_type type;
	__u32 flags;
};

static const struct map_mode_spec map_modes[] = {
	{ RL_MAP_SHARED_GLOBAL, "shared-global", BPF_MAP_TYPE_LRU_HASH, 0 },
	{ RL_MAP_SHARED_LOCAL, "shared-local", BPF_MAP_TYPE_LRU_HASH,
	  BPF_F_NO_COMMON_LRU },
	{ RL_MAP_PERCPU_GLOBAL, "percpu-global", BPF_MAP_TYPE_LRU_PERCPU_HASH, 0 },
	{ RL_MAP_PERCPU_LOCAL, "percpu-local", BPF_MAP_TYPE_LRU_PERCPU_HASH,
	  BPF_F_NO_COMMON_LRU },
	{ RL_MAP_HASH_SHARED, "hash-shared", BPF_MAP_TYPE_HASH, 0 },
	{ RL_MAP_HASH_PERCPU, "hash-percpu", BPF_MAP_TYPE_PERCPU_HASH, 0 },
};

struct options {
	const char *ifname;
	const char *object_path;
	const struct map_mode_spec *map_mode;
	__u32 rate_pps;
	__u32 burst;
	__u32 entries;
	__u32 key_mode;
	__be32 target_saddr;
	int target_enabled;
	int detach;
	int replace;
	__u64 trial_id;
};

static const struct map_mode_spec *find_map_mode(const char *name) {
	for (size_t i = 0; i < sizeof(map_modes) / sizeof(map_modes[0]); i++) {
		if (strcmp(name, map_modes[i].name) == 0)
			return &map_modes[i];
	}
	return NULL;
}

static void usage(const char *program) {
	fprintf(stderr,
		"Usage: %s --interface IFACE [OPTIONS]\n"
		"       %s --interface IFACE --detach\n\n"
		"Options:\n"
		"  -i, --interface IFACE   XDP interface (required)\n"
		"  -r, --rate PPS          Sustained packets/s per key (default: 100)\n"
		"  -b, --burst PACKETS     Immediate packet allowance (default: 10)\n"
		"  -n, --entries COUNT     Maximum map keys (default: 1024)\n"
		"  -k, --key source|flow   Source-IP or IPv4 5-tuple key (default: source)\n"
		"  -m, --map-mode MODE     Map organization (default: percpu-local)\n"
		"      Modes: shared-global, shared-local, percpu-global, percpu-local,\n"
		"             hash-shared, hash-percpu\n"
		"  -o, --object PATH       BPF object (default: ratelimit.bpf.o)\n"
		"      --target-source IP  Audit this source across rl_state evictions\n"
		"      --trial-id ID       Positive integer identity (required with target audit)\n"
		"      --replace           Replace an existing native-XDP program\n"
		"      --detach            Detach the native-XDP program\n"
		"  -h, --help              Show this help\n",
		program, program);
}

static int parse_u32(const char *text, __u32 *value) {
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end != '\0' || parsed == 0 || parsed > UINT_MAX)
		return -1;
	*value = (__u32)parsed;
	return 0;
}

static int parse_options(int argc, char **argv, struct options *options) {
	static const struct option long_options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "rate", required_argument, NULL, 'r' },
		{ "burst", required_argument, NULL, 'b' },
		{ "entries", required_argument, NULL, 'n' },
		{ "key", required_argument, NULL, 'k' },
		{ "map-mode", required_argument, NULL, 'm' },
		{ "object", required_argument, NULL, 'o' },
		{ "replace", no_argument, NULL, 1000 },
		{ "detach", no_argument, NULL, 1001 },
		{ "target-source", required_argument, NULL, 1002 },
		{ "trial-id", required_argument, NULL, 1003 },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "i:r:b:n:k:m:o:h", long_options, NULL)) != -1) {
		switch (opt) {
			case 'i': 
				options->ifname = optarg;
				break;
			case 'r':
				if (parse_u32(optarg, &options->rate_pps)) return -1;
				break;
			case 'b':
				if (parse_u32(optarg, &options->burst)) return -1;
				break;
			case 'n':
				if (parse_u32(optarg, &options->entries)) return -1;
				break;
			case 'k':
				if (strcmp(optarg, "source") == 0)
					options->key_mode = KEY_SADDR;
				else if (strcmp(optarg, "flow") == 0)
					options->key_mode = KEY_FLOW;
				else
					return -1;
				break;
			case 'm':
				options->map_mode = find_map_mode(optarg);
				if (!options->map_mode)
					return -1;
				break;
			case 'o': 
				options->object_path = optarg;
				break;
			case 1000:
				options->replace = 1; 
				break;
			case 1001:
				options->detach = 1; 
				break;
			case 1002: {
				struct in_addr address;

				if (inet_pton(AF_INET, optarg, &address) != 1)
					return -1;
				options->target_saddr = address.s_addr;
				options->target_enabled = 1;
				break;
			}
			case 'h': 
				usage(argv[0]); 
				exit(EXIT_SUCCESS);
			case 1003: {
				char *end;
				errno = 0;
				options->trial_id = strtoull(optarg, &end, 10);
				if (errno || !*optarg || *end || *optarg == '-' ||
				    !options->trial_id)
					return -1;
				break;
			}
			default: 
				return -1;
		}
	}

	return options->ifname && optind == argc &&
		(!options->target_enabled || options->trial_id) ? 0 : -1;
}

int main(int argc, char **argv) {
	struct options options = {
		.object_path = "ratelimit.bpf.o",
		.map_mode = &map_modes[RL_MAP_PERCPU_LOCAL],
		.rate_pps = 100,
		.burst = 10,
		.entries = 1024,
		.key_mode = KEY_SADDR,
	};
	struct bpf_object *object = NULL;
	struct bpf_program *program;
	struct bpf_map *state_map;
	struct rl_config config;
	struct bpf_map_info state_info = {};
	__u32 state_info_size = sizeof(state_info);
	__u64 interval_ns;
	__u32 zero = 0;
	__u32 attach_flags;
	unsigned int ifindex;
	int config_fd;
	int program_fd;
	int err;

	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ifindex = if_nametoindex(options.ifname);
	if (!ifindex) {
		fprintf(stderr, "Unknown interface %s: %s\n", options.ifname, strerror(errno));
		return EXIT_FAILURE;
	}

	attach_flags = XDP_FLAGS_DRV_MODE;
	if (options.detach) {
		err = bpf_xdp_detach(ifindex, attach_flags, NULL);
		if (err) {
			fprintf(stderr, "Could not detach XDP from %s: %s\n",
				    options.ifname, strerror(-err));
			return EXIT_FAILURE;
		}
		printf("Detached native XDP from %s\n", options.ifname);
		return EXIT_SUCCESS;
	}

	interval_ns = RL_NSEC_PER_SEC / options.rate_pps;
	if (interval_ns == 0 || (__u64)(options.burst - 1) > UINT64_MAX / interval_ns) {
		fprintf(stderr, "Rate/burst combination is out of range\n");
		return EXIT_FAILURE;
	}
	config = (struct rl_config) {
		.interval_ns = interval_ns,
		.tolerance_ns = (__u64)(options.burst - 1) * interval_ns,
		.rate_pps = options.rate_pps,
		.burst = options.burst,
		.key_mode = options.key_mode,
		.map_mode = options.map_mode->id,
		.target_saddr = options.target_saddr,
		.target_enabled = options.target_enabled,
		.trial_id = options.trial_id,
	};

	object = bpf_object__open_file(options.object_path, NULL);
	err = libbpf_get_error(object);
	if (err) {
		object = NULL;
		fprintf(stderr, "Could not open %s: %s\n", options.object_path, strerror(-err));
		goto out;
	}

	state_map = bpf_object__find_map_by_name(object, "rl_state");
	if (!state_map) {
		fprintf(stderr, "BPF object has no rl_state map\n");
		err = -ENOENT;
		goto out;
	}
	err = bpf_map__set_max_entries(state_map, options.entries);
	if (err) {
		fprintf(stderr, "Could not set map size: %s\n", strerror(-err));
		goto out;
	}
	err = bpf_map__set_type(state_map, options.map_mode->type);
	if (err) {
		fprintf(stderr, "Could not set map type: %s\n", strerror(-err));
		goto out;
	}
	err = bpf_map__set_map_flags(state_map, options.map_mode->flags);
	if (err) {
		fprintf(stderr, "Could not set map flags: %s\n", strerror(-err));
		goto out;
	}

	err = bpf_object__load(object);
	if (err) {
		fprintf(stderr, "Could not load BPF object: %s\n", strerror(-err));
		goto out;
	}
	err = bpf_obj_get_info_by_fd(bpf_map__fd(state_map), &state_info, &state_info_size);
	if (err) {
		err = -errno;
		fprintf(stderr, "Could not read actual state-map capacity: %s\n", strerror(errno));
		goto out;
	}

	config_fd = bpf_object__find_map_fd_by_name(object, "rl_config");
	if (config_fd < 0) {
		err = config_fd;
		fprintf(stderr, "Could not find config map: %s\n", strerror(-err));
		goto out;
	}
	err = bpf_map_update_elem(config_fd, &zero, &config, BPF_ANY);
	if (err) {
		err = -errno;
		fprintf(stderr, "Could not configure limiter: %s\n", strerror(errno));
		goto out;
	}

	program = bpf_object__find_program_by_name(object, "xdp_ratelimit");
	if (!program) {
		fprintf(stderr, "BPF object has no xdp_ratelimit program\n");
		err = -ENOENT;
		goto out;
	}
	program_fd = bpf_program__fd(program);
	if (!options.replace)
		attach_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	err = bpf_xdp_attach(ifindex, program_fd, attach_flags, NULL);
	if (err) {
		fprintf(stderr, "Could not attach native XDP to %s: %s%s\n",
			    options.ifname, strerror(-err),
			    options.replace ? "" : " (use --replace only if intentional)");
		goto out;
	}

	printf("Attached limiter to %s: rate=%u pps, burst=%u, entries=%u, "
	       "key=%s\n", options.ifname, options.rate_pps, options.burst,
	       options.entries,
	       options.key_mode == KEY_SADDR ? "source" : "flow");
	printf("Map mode: %s\n", options.map_mode->name);
	int possible_cpus = libbpf_num_possible_cpus();
	printf("State capacity: requested=%u actual=%u keys; possible_cpus=%d\n",
	       options.entries, state_info.max_entries, possible_cpus);
	if ((options.map_mode->flags & BPF_F_NO_COMMON_LRU) && possible_cpus > 0)
		printf("Per-CPU LRU partition: %u keys\n",
		       state_info.max_entries / (__u32)possible_cpus);
	if (options.target_enabled) {
		char target[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &options.target_saddr, target, sizeof(target));
		printf("Target audit source: %s; trial_id=%llu\n", target,
		       (unsigned long long)options.trial_id);
	}
	err = 0;

out:
	bpf_object__close(object);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

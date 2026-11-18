"""Load, validate and expand YAML experiment definitions."""

import copy
import ipaddress
import itertools
import re

import yaml

MAP_MODES = {
    "shared-global", "shared-local", "percpu-global", "percpu-local",
    "hash-shared", "hash-percpu",
}
EXPECTATIONS = {"reset", "retained", "either"}
TRANSFORMS = {"auto", "none", "symmetric-or-xor"}
KEY_MODES = {"source", "flow"}
PROTOCOLS = {"udp", "tcp"}
CHAFF_MODES = {"steered", "random"}
MATRIX_NAME_KEYS = {
    "limiter.map_mode": "mode",
    "limiter.entries": "entries",
    "traffic.chaff": "chaff",
}

CONTROLLER_DEFAULTS = {
    "remote_repository": "/local/repository",
    "remote_trial_root": "/tmp/xdp-rss-trials",
    "results_directory": "results",
    "ssh_options": ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"],
    "command_timeout_seconds": 180,
    "require_clean": True,
    "require_same_commit": True,
    "require_setup_ready": True,
    "build": True,
    "run_tests": True,
    "continue_on_failure": False,
}

ALLOWED_SECTIONS = {
    "network": {
        "victim_experiment_ip", "attacker_experiment_ip", "queue_count",
        "stop_irqbalance", "disable_rps", "blackhole_routes", "irq_affinity",
    },
    "rss": {"input_transform", "apply_equal"},
    "limiter": {
        "rate_pps", "burst", "entries", "key", "map_mode", "target_source",
    },
    "traffic": {
        "destination", "source", "key", "protocol", "target_queue", "keys",
        "packets_per_key", "rate_pps", "source_port", "destination_port",
        "warmup_packets", "retry_packets", "deadline_ms", "chaff",
        "dry_run_first",
    },
    "verification": {"expect", "drain_seconds"},
    "cleanup": {"detach"},
}
DERIVED_OPTIONS = {
    "network": {"blackhole_routes"},
    "traffic": {"deadline_ms"},
}


def fail(message):
    raise ValueError(message)


def require_mapping(value, name):
    if not isinstance(value, dict):
        fail(f"{name} must be a mapping")
    return value


def require_bool(value, name):
    if not isinstance(value, bool):
        fail(f"{name} must be true or false")


def require_int(value, name, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{name} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else " or greater"
        fail(f"{name} must be {minimum}{suffix}")


def require_string(value, name):
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        fail(f"{name} must be a nonempty single-line string")


def require_ipv4(value, name):
    require_string(value, name)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        fail(f"{name} must be an IPv4 address: {error}")
    if not isinstance(address, ipaddress.IPv4Address):
        fail(f"{name} must be an IPv4 address")
    return address


def derive_blackhole_routes(traffic):
    if traffic["key"] != "source":
        return []

    base = ipaddress.IPv4Address("10.100.0.0")
    last = int(base) + traffic["keys"]
    excluded = sorted({
        int(require_ipv4(traffic["source"], "traffic.source")),
        int(require_ipv4(traffic["destination"], "traffic.destination")),
    })
    for address in excluded:
        if int(base) < address <= last:
            last += 1
    maximum = int(ipaddress.IPv4Address("10.255.255.255"))
    if last > maximum:
        fail("traffic.keys exhausts the generated source-address chaff range")

    first_network = ipaddress.ip_network(f"{base}/16")
    last_network = ipaddress.ip_network(f"{ipaddress.IPv4Address(last)}/16", strict=False)
    return [
        str(network)
        for network in ipaddress.summarize_address_range(
            first_network.network_address, last_network.broadcast_address
        )
    ]


def derive_deadline_ms(rate_pps):
    interval_ms = 1000 // rate_pps
    return max(1, interval_ms * 9 // 10)


def deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def dotted_get(mapping, path):
    current = mapping
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            fail(f"matrix path does not exist in defaults/overrides: {path}")
        current = current[part]
    return current


def dotted_set(mapping, path, value):
    parts = path.split(".")
    current = mapping
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            fail(f"matrix path does not exist in defaults/overrides: {path}")
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        fail(f"matrix path does not exist in defaults/overrides: {path}")
    current[parts[-1]] = copy.deepcopy(value)


def safe_name(value):
    name = re.sub(r"[^A-Za-z0-9-]+", "-", str(value)).strip("-")
    return name[:120] or "trial"


def validate_trial(trial):
    unknown_sections = set(trial) - set(ALLOWED_SECTIONS)
    if unknown_sections:
        fail(f"unknown trial sections: {', '.join(sorted(unknown_sections))}")

    missing = set(ALLOWED_SECTIONS) - set(trial)
    if missing:
        fail(f"missing trial sections: {', '.join(sorted(missing))}")

    for section, allowed in ALLOWED_SECTIONS.items():
        values = require_mapping(trial[section], section)
        unknown = set(values) - allowed
        if unknown:
            fail(f"unknown {section} options: {', '.join(sorted(unknown))}")

        missing_options = allowed - DERIVED_OPTIONS.get(section, set()) - set(values)
        if missing_options:
            fail(f"missing {section} options: {', '.join(sorted(missing_options))}")

    network = trial["network"]
    for key in ("victim_experiment_ip", "attacker_experiment_ip"):
        require_ipv4(network[key], f"network.{key}")
    require_int(network["queue_count"], "network.queue_count", 1, 64)
    require_bool(network["stop_irqbalance"], "network.stop_irqbalance")
    require_bool(network["disable_rps"], "network.disable_rps")
    affinity = require_mapping(network["irq_affinity"], "network.irq_affinity")
    if set(affinity) != {"enabled", "name_pattern", "cpus"}:
        fail("network.irq_affinity requires enabled, name_pattern and cpus")
    require_bool(affinity["enabled"], "network.irq_affinity.enabled")
    require_string(affinity["name_pattern"], "network.irq_affinity.name_pattern")
    if "{queue}" not in affinity["name_pattern"]:
        fail("network.irq_affinity.name_pattern must contain {queue}")
    if not isinstance(affinity["cpus"], list):
        fail("network.irq_affinity.cpus must be a list")
    if affinity["enabled"] and len(affinity["cpus"]) != network["queue_count"]:
        fail("network.irq_affinity.cpus must contain one CPU per queue")
    for cpu in affinity["cpus"]:
        require_int(cpu, "network.irq_affinity CPU", 0)

    rss = trial["rss"]
    if rss["input_transform"] not in TRANSFORMS:
        fail(f"rss.input_transform must be one of {sorted(TRANSFORMS)}")
    require_bool(rss["apply_equal"], "rss.apply_equal")

    limiter = trial["limiter"]
    require_int(limiter["rate_pps"], "limiter.rate_pps", 1)
    require_int(limiter["burst"], "limiter.burst", 1)
    require_int(limiter["entries"], "limiter.entries", 1)
    if limiter["key"] not in KEY_MODES:
        fail(f"limiter.key must be one of {sorted(KEY_MODES)}")
    if limiter["map_mode"] not in MAP_MODES:
        fail(f"limiter.map_mode must be one of {sorted(MAP_MODES)}")
    require_ipv4(limiter["target_source"], "limiter.target_source")

    traffic = trial["traffic"]
    for key in ("destination", "source"):
        require_ipv4(traffic[key], f"traffic.{key}")
    if traffic["key"] not in KEY_MODES:
        fail(f"traffic.key must be one of {sorted(KEY_MODES)}")
    if traffic["protocol"] not in PROTOCOLS:
        fail(f"traffic.protocol must be one of {sorted(PROTOCOLS)}")
    if traffic["chaff"] not in CHAFF_MODES:
        fail(f"traffic.chaff must be one of {sorted(CHAFF_MODES)}")
    if traffic["target_queue"] is not None:
        require_int(traffic["target_queue"], "traffic.target_queue", 0,
                    network["queue_count"] - 1)
    for key, minimum, maximum in (
        ("keys", 1, 10223615), ("packets_per_key", 1, None),
        ("rate_pps", 0, 1000000000), ("source_port", 1, 65535),
        ("destination_port", 1, 65535), ("warmup_packets", 1, None),
        ("retry_packets", 1, None),
    ):
        require_int(traffic[key], f"traffic.{key}", minimum, maximum)
    require_bool(traffic["dry_run_first"], "traffic.dry_run_first")

    if "blackhole_routes" not in network:
        network["blackhole_routes"] = derive_blackhole_routes(traffic)
    if "deadline_ms" not in traffic:
        traffic["deadline_ms"] = derive_deadline_ms(limiter["rate_pps"])

    if not isinstance(network["blackhole_routes"], list):
        fail("network.blackhole_routes must be a list")
    for route in network["blackhole_routes"]:
        require_string(route, "network.blackhole_routes entry")
        try:
            route_network = ipaddress.ip_network(route)
        except ValueError as error:
            fail(f"network.blackhole_routes entry must be a network: {error}")
        if not isinstance(route_network, ipaddress.IPv4Network):
            fail("network.blackhole_routes entries must be IPv4 networks")
    require_int(traffic["deadline_ms"], "traffic.deadline_ms", 1)

    verification = trial["verification"]
    if verification["expect"] not in EXPECTATIONS:
        fail(f"verification.expect must be one of {sorted(EXPECTATIONS)}")
    if isinstance(verification["drain_seconds"], bool) or not isinstance(
            verification["drain_seconds"], (int, float)) or verification["drain_seconds"] < 0:
        fail("verification.drain_seconds must be a nonnegative number")
    require_bool(trial["cleanup"]["detach"], "cleanup.detach")

    if limiter["key"] != "source" or traffic["key"] != "source":
        fail("verified attack trials currently require source keys")
    if limiter["target_source"] != traffic["source"]:
        fail("limiter.target_source must equal traffic.source")
    if traffic["destination"] != network["victim_experiment_ip"]:
        fail("traffic.destination must equal network.victim_experiment_ip")
    if traffic["source"] != network["attacker_experiment_ip"]:
        fail("traffic.source must equal network.attacker_experiment_ip")


def expand_experiments(document):
    defaults = require_mapping(document.get("defaults"), "defaults")
    experiments = document.get("experiments")
    if not isinstance(experiments, list) or not experiments:
        fail("experiments must be a nonempty list")

    expanded = []
    for index, experiment in enumerate(experiments):
        experiment = require_mapping(experiment, f"experiments[{index}]")
        unknown = set(experiment) - {"name", "overrides", "matrix", "repetitions"}
        if unknown:
            fail(f"unknown experiment options: {', '.join(sorted(unknown))}")

        require_string(experiment.get("name"), f"experiments[{index}].name")
        overrides = require_mapping(experiment.get("overrides", {}), "overrides")
        base = deep_merge(defaults, overrides)
        matrix = require_mapping(experiment.get("matrix", {}), "matrix")
        repetitions = experiment.get("repetitions", 1)
        require_int(repetitions, "repetitions", 1)

        paths = list(matrix)
        choices = []
        for path in paths:
            require_string(path, "matrix path")
            dotted_get(base, path)
            values = matrix[path]
            if not isinstance(values, list) or not values:
                fail(f"matrix value for {path} must be a nonempty list")
            choices.append(values)

        products = itertools.product(*choices) if choices else [()]
        for combination in products:
            trial = copy.deepcopy(base)
            labels = []
            for path, value in zip(paths, combination):
                dotted_set(trial, path, value)
                key = MATRIX_NAME_KEYS.get(path, safe_name(path))
                labels.append(f"{key}-{safe_name(value)}")

            validate_trial(trial)
            base_name = "_".join([safe_name(experiment["name"]), *labels])[:120].rstrip("-_")
            for repetition in range(1, repetitions + 1):
                name = base_name if repetitions == 1 else f"{base_name}_r{repetition:02d}"
                expanded.append({"name": name, "settings": copy.deepcopy(trial)})

    return expanded


def load_configuration(path):
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        fail(f"could not read YAML configuration: {error}")

    document = require_mapping(document, "configuration")
    if document.get("version") != 1:
        fail("configuration version must be 1")
    unknown = set(document) - {"version", "controller", "defaults", "experiments"}
    if unknown:
        fail(f"unknown top-level options: {', '.join(sorted(unknown))}")

    controller = deep_merge(CONTROLLER_DEFAULTS,
                            require_mapping(document.get("controller", {}), "controller"))
    unknown_controller = set(controller) - set(CONTROLLER_DEFAULTS)
    if unknown_controller:
        fail(f"unknown controller options: {', '.join(sorted(unknown_controller))}")
    for key in ("remote_repository", "remote_trial_root", "results_directory"):
        require_string(controller[key], f"controller.{key}")
    if not controller["remote_repository"].startswith("/") or not controller[
            "remote_trial_root"].startswith("/"):
        fail("remote repository and trial root must be absolute paths")
    if not isinstance(controller["ssh_options"], list) or not all(
            isinstance(option, str) for option in controller["ssh_options"]):
        fail("controller.ssh_options must be a list of strings")
    require_int(controller["command_timeout_seconds"],
                "controller.command_timeout_seconds", 1)
    for key in ("require_clean", "require_same_commit", "require_setup_ready",
                "build", "run_tests", "continue_on_failure"):
        require_bool(controller[key], f"controller.{key}")

    return controller, expand_experiments(document)

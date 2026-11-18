#!/usr/bin/env python3
"""Run one or more verified RSS/LRU experiments over management SSH."""

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment_config import fail, load_configuration

UTC = timezone.utc  # noqa: UP017 - keep the controller compatible with Python 3.9/3.10
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_VERIFIER = REPOSITORY_ROOT / "victim/ratelimit/verify_attack.py"
REMOTE_HELPERS = [
    "scripts/remote/common.sh",
    "scripts/remote/prepare_victim.sh",
    "scripts/remote/prepare_attacker.sh",
    "scripts/remote/attach_limiter.sh",
    "scripts/remote/run_traffic.sh",
    "scripts/remote/capture_evidence.py",
    "scripts/remote/capture_evidence.sh",
    "scripts/remote/detach_limiter.sh",
    "scripts/remote/preflight.py",
]


class TrialError(RuntimeError):
    pass


def shell_join(arguments):
    return " ".join(shlex.quote(str(argument)) for argument in arguments)


class RemoteController:
    def __init__(self, victim, attacker, settings, log_path):
        self.hosts = {"victim": victim, "attacker": attacker}
        self.settings = settings
        self.log_path = log_path

    def log(self, text):
        with self.log_path.open("a", encoding="utf-8") as output:
            output.write(text)
            if not text.endswith("\n"):
                output.write("\n")

    def local(self, command, label, *, check=True, timeout=None):
        self.log(f"\n## {label}\n$ {shell_join(command)}")
        result = subprocess.run(command, check=False, text=True, capture_output=True,
                                timeout=timeout or self.settings["command_timeout_seconds"])
        self.log(result.stdout)
        self.log(result.stderr)
        if check and result.returncode:
            raise TrialError(f"{label} failed with exit status {result.returncode}: "
                             f"{result.stderr.strip()[-500:]}")
        return result

    def remote(self, role, script, label, *, check=True, timeout=None):
        command = ["ssh", *self.settings["ssh_options"], self.hosts[role], "bash", "-se"]
        self.log(f"\n## {label} on {role} ({self.hosts[role]})\n{script.rstrip()}")
        result = subprocess.run(command, check=False,
                                input="set -euo pipefail\n" + script,
                                text=True, capture_output=True,
                                timeout=timeout or self.settings["command_timeout_seconds"])
        self.log(result.stdout)
        self.log(result.stderr)
        if check and result.returncode:
            raise TrialError(f"{label} on {role} failed with exit status "
                             f"{result.returncode}: {result.stderr.strip()[-500:]}")
        return result

    def remote_command(self, role, arguments, label, *, check=True, timeout=None):
        return self.remote(role, shell_join(arguments) + "\n", label,
                           check=check, timeout=timeout)

    def download(self, role, remote_path, local_path, label):
        command = ["scp", *self.settings["ssh_options"],
                   f"{self.hosts[role]}:{remote_path}", str(local_path)]
        return self.local(command, label)

    def upload(self, role, local_path, remote_path, label):
        command = ["scp", *self.settings["ssh_options"], str(local_path),
                   f"{self.hosts[role]}:{remote_path}"]
        return self.local(command, label)


def remote_preflight(controller, role):
    repo = controller.settings["remote_repository"]
    command = [
        "python3", f"{repo}/scripts/remote/preflight.py", "--repository", repo,
    ]
    for option, enabled in (
        ("--require-setup-ready", controller.settings["require_setup_ready"]),
        ("--build", controller.settings["build"]),
        ("--run-tests", controller.settings["run_tests"]),
    ):
        if enabled:
            command.append(option)

    result = controller.remote_command(role, command, "preflight")
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise TrialError(f"could not parse {role} preflight output: {error}") from error


def verify_remote_sync(controller):
    victim = remote_preflight(controller, "victim")
    attacker = remote_preflight(controller, "attacker")

    if controller.settings["require_clean"] and (victim["dirty"] or attacker["dirty"]):
        raise TrialError("remote repository has tracked modifications")
    if controller.settings["require_same_commit"] and victim["commit"] != attacker["commit"]:
        raise TrialError("victim and attacker repository commits differ")
    if victim["sha256"] != attacker["sha256"]:
        raise TrialError("victim and attacker binaries/scripts differ")

    local_files = ["victim/ratelimit/verify_attack.py", *REMOTE_HELPERS]
    for relative in local_files:
        local_hash = hashlib.sha256((REPOSITORY_ROOT / relative).read_bytes()).hexdigest()
        if victim["sha256"].get(relative) != local_hash:
            raise TrialError(f"controller and remote implementation differ: {relative}")

    return victim["commit"], victim["sha256"]


def prepare_nodes(controller, settings, remote_dir):
    repo = controller.settings["remote_repository"]
    network = settings["network"]
    affinity = network["irq_affinity"]
    victim_command = [
        "bash", f"{repo}/scripts/remote/prepare_victim.sh",
        remote_dir,
        network["victim_experiment_ip"],
        network["queue_count"],
        int(network["stop_irqbalance"]),
        int(network["disable_rps"]),
        int(affinity["enabled"]),
        affinity["name_pattern"],
        ",".join(map(str, affinity["cpus"])),
        *network["blackhole_routes"],
    ]
    controller.remote_command("victim", victim_command, "prepare victim network")

    attacker_command = [
        "bash", f"{repo}/scripts/remote/prepare_attacker.sh",
        remote_dir,
        network["attacker_experiment_ip"],
        network["victim_experiment_ip"],
    ]
    controller.remote_command("attacker", attacker_command, "prepare attacker network")


def attach_and_export(controller, settings, trial_id, remote_dir):
    repo = controller.settings["remote_repository"]
    network = settings["network"]
    limiter = settings["limiter"]
    rss = settings["rss"]
    command = [
        "bash", f"{repo}/scripts/remote/attach_limiter.sh",
        repo,
        remote_dir,
        network["victim_experiment_ip"],
        network["queue_count"],
        limiter["rate_pps"],
        limiter["burst"],
        limiter["entries"],
        limiter["key"],
        limiter["map_mode"],
        limiter["target_source"],
        trial_id,
        rss["input_transform"],
        int(rss["apply_equal"]),
    ]
    controller.remote_command("victim", command, "attach limiter and export RSS")


def traffic_arguments(settings, trial_id, rss_path, summary_path, repo, dry_run=False):
    network = settings["network"]
    traffic = settings["traffic"]
    return [
        "bash", f"{repo}/scripts/remote/run_traffic.sh",
        repo,
        network["attacker_experiment_ip"],
        traffic["destination"],
        traffic["source"],
        traffic["key"],
        traffic["protocol"],
        traffic["keys"],
        traffic["packets_per_key"],
        traffic["rate_pps"],
        rss_path,
        traffic["source_port"],
        traffic["destination_port"],
        traffic["warmup_packets"],
        traffic["retry_packets"],
        traffic["deadline_ms"],
        trial_id,
        traffic["chaff"],
        "" if traffic["target_queue"] is None else traffic["target_queue"],
        int(dry_run),
        summary_path,
    ]


def capture_evidence(controller, settings, remote_dir):
    repo = controller.settings["remote_repository"]
    victim_ip = settings["network"]["victim_experiment_ip"]
    drain = settings["verification"]["drain_seconds"]
    command = [
        "bash", f"{repo}/scripts/remote/capture_evidence.sh",
        repo, victim_ip, remote_dir, drain,
    ]
    controller.remote_command("victim", command, "capture victim evidence")


def detach(controller, settings):
    repo = controller.settings["remote_repository"]
    victim_ip = settings["network"]["victim_experiment_ip"]
    command = [
        "bash", f"{repo}/scripts/remote/detach_limiter.sh", repo, victim_ip,
    ]
    controller.remote_command("victim", command, "detach limiter", check=False)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def archive_trial_extras(work_dir, result_dir, manifest):
    result_dir.mkdir(parents=True, exist_ok=True)
    for source in work_dir.iterdir():
        if source.is_file() and not (result_dir / source.name).exists():
            shutil.copy2(source, result_dir / source.name)
    write_json(result_dir / "manifest.json", manifest)


def run_one_trial(controller, experiment, commit, hashes, results_root):
    settings = experiment["settings"]
    trial_id = time.time_ns()
    result_dir = results_root / f"{experiment['name']}-{trial_id}"
    if result_dir.exists():
        raise TrialError(f"result directory already exists: {result_dir}")
    work_dir = Path(tempfile.mkdtemp(prefix=f"xdp-rss-{trial_id}-"))
    remote_dir = f"{controller.settings['remote_trial_root'].rstrip('/')}/{trial_id}"
    manifest = {
        "version": 1,
        "name": experiment["name"],
        "trial_id": trial_id,
        "created_utc": datetime.now(UTC).isoformat(),
        "victim": controller.hosts["victim"],
        "attacker": controller.hosts["attacker"],
        "repository_commit": commit,
        "artifact_sha256": hashes,
        "settings": settings,
        "status": "running",
    }
    attached = False

    try:
        prepare_nodes(controller, settings, remote_dir)
        attached = True
        attach_and_export(controller, settings, trial_id, remote_dir)
        rss_local = work_dir / "rss.conf"
        controller.download("victim", f"{remote_dir}/rss.conf", rss_local,
                            "download RSS configuration")
        controller.download("victim", f"{remote_dir}/victim-diagnostics.txt",
                            work_dir / "victim-diagnostics.txt", "download diagnostics")
        controller.upload("attacker", rss_local, f"{remote_dir}/rss.conf",
                          "upload RSS configuration")

        repo = controller.settings["remote_repository"]
        if settings["traffic"]["dry_run_first"]:
            controller.remote_command(
                "attacker",
                traffic_arguments(settings, trial_id, f"{remote_dir}/rss.conf", "",
                                  repo, True),
                "attack dry run",
            )
        attack_result = controller.remote_command(
            "attacker",
            traffic_arguments(settings, trial_id, f"{remote_dir}/rss.conf",
                              f"{remote_dir}/attack.json", repo),
            "execute attack",
        )
        (work_dir / "attacker.stdout.log").write_text(attack_result.stdout,
                                                       encoding="utf-8")
        (work_dir / "attacker.stderr.log").write_text(attack_result.stderr,
                                                       encoding="utf-8")

        capture_evidence(controller, settings, remote_dir)
        attack_local = work_dir / "attack.json"
        evidence_local = work_dir / "evidence.json"
        controller.download("attacker", f"{remote_dir}/attack.json", attack_local,
                            "download attack summary")
        controller.download("victim", f"{remote_dir}/evidence.json", evidence_local,
                            "download victim evidence")

        expect = settings["verification"]["expect"]
        verify_result = controller.local([
            sys.executable, str(LOCAL_VERIFIER),
            "--summary", str(attack_local),
            "--evidence", str(evidence_local),
            "--expect", expect,
            "--results-dir", str(results_root.resolve()),
            "--result-name", experiment["name"],
        ], "verify trial", check=False)

        verification_local = result_dir / "verification.json"
        if not verification_local.is_file():
            raise TrialError("verifier did not create the canonical result archive")
        report = json.loads(verification_local.read_text(encoding="utf-8"))
        manifest["verification"] = report
        if verify_result.returncode:
            raise TrialError(f"verification did not produce expected outcome {expect}")
        manifest["status"] = "passed"
        archive_trial_extras(work_dir, result_dir, manifest)
        return True, result_dir

    except (OSError, ValueError, TrialError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        archive_trial_extras(work_dir, result_dir, manifest)
        return False, result_dir

    finally:
        try:
            if attached and settings["cleanup"]["detach"]:
                detach(controller, settings)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--victim", required=True, help="victim management SSH destination")
    parser.add_argument("--attacker", required=True, help="attacker management SSH destination")
    parser.add_argument("--config", required=True, type=Path, help="YAML experiment definition")
    parser.add_argument("--plan", action="store_true",
                        help="validate and print expanded trials only")
    args = parser.parse_args()

    try:
        if args.victim == args.attacker:
            fail("victim and attacker SSH destinations must differ")
        controller_settings, experiments = load_configuration(args.config)
        if args.plan:
            print(json.dumps(experiments, indent=2))
            return 0

        results_root = Path(controller_settings["results_directory"])
        results_root.mkdir(parents=True, exist_ok=True)
        session = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        log_path = results_root / f"orchestrator-{session}.log"
        controller = RemoteController(args.victim, args.attacker,
                                      controller_settings, log_path)
        commit, hashes = verify_remote_sync(controller)

        failures = []
        for number, experiment in enumerate(experiments, 1):
            print(f"[{number}/{len(experiments)}] {experiment['name']}", flush=True)
            passed, result_dir = run_one_trial(controller, experiment, commit, hashes,
                                               results_root)
            print(f"  {'PASS' if passed else 'FAIL'}: {result_dir}", flush=True)
            if not passed:
                failures.append(experiment["name"])
                if not controller_settings["continue_on_failure"]:
                    break

        if failures:
            raise TrialError("failed experiments: " + ", ".join(failures))
        return 0

    except (OSError, ValueError, TrialError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        parser.exit(1, f"ERROR: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())

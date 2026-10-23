#!/usr/bin/env python3
"""Validate the deployed benchmark fleet from captured Kubernetes JSON and startup logs."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def validate(pods, configmaps, logs, parties, tokio, rayon, preproc, tuning):
    """Return a verified fleet inventory, or reject incomplete and mixed configurations."""
    expected = {f"kms-core-{i}-core-{i}" for i in range(1, parties + 1)}
    actual = {pod["metadata"]["name"] for pod in pods["items"]}
    if actual != expected:
        raise ValueError(f"expected party pods {sorted(expected)}, found {sorted(actual)}")
    configs = {cm["metadata"]["name"]: cm.get("data", {}) for cm in configmaps["items"]}
    requested = dict(pair.split("=", 1) for pair in tuning.split(",") if pair)
    fleet = {}
    for pod in pods["items"]:
        metadata, spec, status = pod["metadata"], pod["spec"], pod.get("status", {})
        name = metadata["name"]
        if metadata.get("deletionTimestamp") or not any(
            c["type"] == "Ready" and c["status"] == "True" for c in status.get("conditions", [])
        ):
            raise ValueError(f"{name}: pod is not Ready")
        mounted = [configs.get(v["configMap"]["name"], {}) for v in spec.get("volumes", []) if "configMap" in v]
        bodies = [cm["kms-server.toml"] for cm in mounted if "kms-server.toml" in cm]
        if len(bodies) != 1:
            raise ValueError(f"{name}: expected one mounted kms-server.toml")
        body = bodies[0]
        for key, value in (("num_tokio_threads", tokio), ("num_rayon_threads", rayon), ("num_sessions_preproc", preproc)):
            matches = re.findall(rf"^\s*{key}\s*=\s*(\d+)\s*(?:#.*)?$", body, re.M)
            if matches != [str(value)]:
                raise ValueError(f"{name}: {key} does not match {value}")
        log = logs[name]
        runtime = re.findall(r"benchmark runtime: tokio=(\d+) rayon=(\d+) preproc=(\d+)", log)
        if runtime != [(str(tokio), str(rayon), str(preproc))]:
            raise ValueError(f"{name}: process startup does not confirm the requested runtime")
        exported = re.findall(r"tuning: exporting ([A-Z][A-Z0-9_]*)=(\S+) into the process environment", log)
        if len(exported) != len(dict(exported)) or dict(exported) != requested:
            raise ValueError(f"{name}: process tuning exports differ from the requested table")
        containers = status.get("containerStatuses", []) + status.get("initContainerStatuses", [])
        declared = {c["name"]: c for c in spec.get("containers", []) + spec.get("initContainers", [])}
        if set(declared) != {c["name"] for c in containers}:
            raise ValueError(f"{name}: container status inventory is incomplete")
        images = {}
        for container in containers:
            if not container.get("imageID"):
                raise ValueError(f"{name}: missing image identity for {container['name']}")
            images[container["name"]] = {
                "image_id": container["imageID"],
                "restarts": container.get("restartCount", 0),
                "started_at": container.get("state", {}).get("running", {}).get("startedAt"),
                "runtime_spec_sha256": hashlib.sha256(json.dumps({
                    key: declared[container["name"]].get(key)
                    for key in ("args", "command", "env", "envFrom", "resources", "securityContext")
                }, sort_keys=True).encode()).hexdigest(),
            }
        main_containers = {c["name"] for c in spec.get("containers", [])} & {"kms-core", "kms-core-enclave"}
        if len(main_containers) != 1:
            raise ValueError(f"{name}: expected exactly one kms-core or kms-core-enclave main container")
        fleet[name] = {
            "uid": metadata["uid"], "node": spec["nodeName"], "containers": images,
            "config_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "enclave_config_sha256": hashlib.sha256(json.dumps(
                [cm.get("enclave.json") for cm in mounted if "kms-server.toml" in cm],
                sort_keys=True).encode()).hexdigest(),
        }
    signatures = {json.dumps({name: c["image_id"] for name, c in p["containers"].items()}, sort_keys=True) for p in fleet.values()}
    if len(signatures) != 1:
        raise ValueError("party container images differ across the fleet")
    return fleet


def check_continuity(previous, current, restarted=False):
    """Require either new pod identities or an unchanged fleet throughout measurement."""
    if previous.keys() != current.keys():
        raise ValueError("party set changed")
    for name in previous:
        if restarted:
            if previous[name]["uid"] == current[name]["uid"]:
                raise ValueError(f"{name}: pod did not restart")
        elif previous[name] != current[name]:
            raise ValueError(f"{name}: pod, configuration, image, or restart state changed during measurement")


def check_reference(reference, current):
    """Keep placement, images, resources and enclave configuration fixed across an A/B pair."""
    if reference.keys() != current.keys():
        raise ValueError("party set differs from REFERENCE_FLEET")
    for name, entry in current.items():
        old = reference[name]
        for key in ("node", "enclave_config_sha256"):
            if old[key] != entry[key]:
                raise ValueError(f"{name}: {key} differs from REFERENCE_FLEET")
        if old["containers"].keys() != entry["containers"].keys():
            raise ValueError(f"{name}: container set differs from REFERENCE_FLEET")
        for container, identity in entry["containers"].items():
            for key in ("image_id", "runtime_spec_sha256"):
                if old["containers"][container][key] != identity[key]:
                    raise ValueError(f"{name}/{container}: {key} differs from REFERENCE_FLEET")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--parties", type=int, required=True)
    for key in ("tokio", "rayon", "preproc"):
        parser.add_argument(f"--{key}", type=int, required=True)
    parser.add_argument("--tuning", default="")
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    pods = json.loads((args.directory / "pods.json").read_text())
    configs = json.loads((args.directory / "configmaps.json").read_text())
    logs = {pod["metadata"]["name"]: (args.directory / f"{pod['metadata']['name']}.log").read_text()
            for pod in pods["items"]}
    fleet = validate(pods, configs, logs, args.parties, args.tokio, args.rayon, args.preproc, args.tuning)
    if args.previous:
        check_continuity(json.loads(args.previous.read_text()), fleet)
    json.dump(fleet, sys.stdout, sort_keys=True, indent=2)
    print()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        sys.exit(f"invalid benchmark fleet: {error}")

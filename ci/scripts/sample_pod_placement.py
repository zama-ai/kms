"""Records core and rate-test client placement from ENA endpoint metadata."""

import argparse
import time

from perf_common import cli, kube_json, timestamp, tsv


def placement_rows(pods, slices, stamp):
    pods = pods.get("items", [])

    def labels(pod):
        return pod.get("metadata", {}).get("labels", {})

    if sum(labels(pod).get("app") == "kms-core" for pod in pods) < 13:
        return []
    if not any("-rate-" in labels(pod).get("test", "") for pod in pods):
        return []
    endpoints = {}
    for item in slices.get("items", []):
        for endpoint in item.get("endpoints", []):
            endpoints.setdefault(endpoint.get("nodeName"), endpoint)
    rows = []
    for pod in pods:
        spec = pod.get("spec", {})
        node = spec.get("nodeName")
        if not node:
            continue
        is_core = labels(pod).get("app") == "kms-core"
        is_rate_test = "-rate-" in labels(pod).get("test", "")
        if not is_core and not is_rate_test:
            continue
        endpoint = endpoints.get(node, {})
        topology = endpoint.get("deprecatedTopology") or {}
        selector = spec.get("nodeSelector") or {}
        rows.append(
            [
                stamp,
                pod["metadata"].get("name", "-"),
                labels(pod).get("workflows.argoproj.io/node-name", "-"),
                node,
                endpoint.get("zone") or topology.get("topology.kubernetes.io/zone", "-"),
                topology.get("node.kubernetes.io/instance-type")
                or selector.get("node.kubernetes.io/instance-type", "-"),
                topology.get("karpenter.sh/nodepool") or selector.get("karpenter.sh/nodepool", "-"),
            ]
        )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("interval", nargs="?", type=float, default=5)
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("interval must be positive")
    print("timestamp\tpod\tworkflow_node\tnode\tzone\tinstance_type\tnodepool", flush=True)
    for _ in range(180):
        stamp = timestamp()
        pods = kube_json(args.namespace, "get", "pods")
        slices = kube_json(
            args.namespace,
            "get",
            "endpointslices.discovery.k8s.io",
            "-l",
            "kubernetes.io/service-name=ena-probe-placement",
        )
        rows = placement_rows(pods, slices, stamp)
        if rows and all(row[4] != "-" for row in rows):
            print("\n".join(sorted({tsv(row) for row in rows})), flush=True)
            return
        time.sleep(args.interval)
    print("# sampler_warning complete topology unavailable after 15 minutes", flush=True)


if __name__ == "__main__":
    cli(main)

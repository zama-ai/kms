#!/usr/bin/env bash
# Join KMS core and rate-test client pods with their node and availability-zone information.
# sample_perf_diagnostics.sh starts this during the performance-testing workflow.
# Output is a tab-separated placement report on stdout after the first rate-test client appears.
set -uo pipefail

namespace="${1:-kms-ci}"
interval="${2:-5}"
tmp_root="$(mktemp -d)"

cleanup() {
  trap - EXIT INT TERM
  rm -rf "${tmp_root}"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

printf 'timestamp\tpod\tworkflow_node\tnode\tzone\tinstance_type\tnodepool\n'
for _attempt in {1..180}; do
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if kubectl get --request-timeout=10s pods -n "${namespace}" -o json \
       > "${tmp_root}/pods.json" 2>/dev/null &&
     kubectl get --request-timeout=10s endpointslices.discovery.k8s.io -n "${namespace}" \
       -l kubernetes.io/service-name=ena-probe-placement -o json \
       > "${tmp_root}/slices.json" 2>/dev/null; then
    if jq -e '([.items[] | select((.metadata.labels.app // "") == "kms-core")] | length) >= 13
      and any(.items[]; ((.metadata.labels.test // "") | contains("-rate-")))' \
      "${tmp_root}/pods.json" >/dev/null; then
      jq -r --slurpfile slices "${tmp_root}/slices.json" --arg ts "${timestamp}" '
        def endpoint_for($name):
          ([$slices[0].items[]?.endpoints[]? | select(.nodeName == $name)][0] // {});
        .items[]
        | select((.spec.nodeName // "") != "")
        | select((.metadata.labels.app // "") == "kms-core"
            or ((.metadata.labels.test // "") | contains("-rate-")))
        | . as $pod
        | endpoint_for($pod.spec.nodeName) as $endpoint
        | [$ts, ($pod.metadata.name // "-"),
           ($pod.metadata.labels["workflows.argoproj.io/node-name"] // "-"),
           ($pod.spec.nodeName // "-"),
           ($endpoint.zone // $endpoint.deprecatedTopology["topology.kubernetes.io/zone"] // "-"),
           ($endpoint.deprecatedTopology["node.kubernetes.io/instance-type"] //
             $pod.spec.nodeSelector["node.kubernetes.io/instance-type"] // "-"),
           ($endpoint.deprecatedTopology["karpenter.sh/nodepool"] //
             $pod.spec.nodeSelector["karpenter.sh/nodepool"] // "-")]
        | @tsv
      ' "${tmp_root}/pods.json" | sort -u > "${tmp_root}/placement.tsv"
      if [[ -s "${tmp_root}/placement.tsv" ]] &&
         awk -F '\t' '$5 == "-" { missing = 1 } END { exit missing }' \
           "${tmp_root}/placement.tsv"; then
        cat "${tmp_root}/placement.tsv"
        exit 0
      fi
    fi
  fi
  sleep "${interval}"
done

echo "# sampler_warning complete topology unavailable after 15 minutes"
exit 0

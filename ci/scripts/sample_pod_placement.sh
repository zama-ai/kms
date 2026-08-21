#!/usr/bin/env bash
# Wait for the first rate-test core-client, then record one AZ placement snapshot
# containing it, the setup client pods, and all KMS cores.
# A headless Service over the ENA probes exposes node names and zones through a
# namespaced EndpointSlice, avoiding cluster-scoped Node API permissions.
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-5}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
JQ_BIN="${JQ_BIN:-jq}"

tmp_root="$(mktemp -d)"
# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT

current_file="${tmp_root}/current.tsv"
pods_file="${tmp_root}/pods.json"
sample_ts=""
touch "${current_file}"

printf '# sampler_start=%s namespace=%s interval=%ss\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NS}" "${INTERVAL}"
printf 'timestamp\tpod\tworkflow_node\tnode\tzone\tinstance_type\tnodepool\n'

single_line() {
  tr '\n' ' ' < "$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

sample_once() {
  local slices_file pods_error slices_error
  sample_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  slices_file="${tmp_root}/endpoint-slices.json"
  pods_error="${tmp_root}/pods-error"
  slices_error="${tmp_root}/endpoint-slices-error"
  if ! "${KUBECTL_BIN}" get pods -n "${NS}" -o json \
    > "${pods_file}" 2> "${pods_error}"; then
    printf '# %s sampler_error pod_discovery="%s"\n' \
      "${sample_ts}" "$(single_line "${pods_error}")"
    return 1
  fi
  if ! "${KUBECTL_BIN}" get endpointslices.discovery.k8s.io -n "${NS}" \
    -l kubernetes.io/service-name=ena-probe-placement -o json \
    > "${slices_file}" 2> "${slices_error}"; then
    printf '# %s sampler_error endpoint_slice_discovery="%s"\n' \
      "${sample_ts}" "$(single_line "${slices_error}")"
    return 1
  fi

  # The single-quoted program is jq syntax; none of its `$` variables are shell variables.
  # shellcheck disable=SC2016
  if ! "${JQ_BIN}" -r --slurpfile slices "${slices_file}" '
    def endpoint_for($name):
      ([$slices[0].items[]?.endpoints[]? | select(.nodeName == $name)][0] // {});

    .items[]
    | select((.spec.nodeName // "") != "")
    | select(
        (.metadata.labels.app // "") == "kms-core"
        or ((.metadata.labels["workflows.argoproj.io/workflow"] // "") | startswith("kms-perf-"))
    )
    | . as $pod
    | endpoint_for($pod.spec.nodeName) as $endpoint
    | [
        ($pod.metadata.name // "-"),
        ($pod.metadata.labels["workflows.argoproj.io/node-name"] // "-"),
        ($pod.spec.nodeName // "-"),
        ($endpoint.zone //
          $endpoint.deprecatedTopology["topology.kubernetes.io/zone"] //
          $endpoint.deprecatedTopology["failure-domain.beta.kubernetes.io/zone"] // "-"),
        ($endpoint.deprecatedTopology["node.kubernetes.io/instance-type"] //
          $pod.spec.nodeSelector["node.kubernetes.io/instance-type"] // "-"),
        ($endpoint.deprecatedTopology["karpenter.sh/nodepool"] //
          $pod.spec.nodeSelector["karpenter.sh/nodepool"] // "-")
      ]
    | @tsv
  ' "${pods_file}" | sort -u > "${current_file}"; then
    printf '# %s sampler_error placement_join_failed\n' "${sample_ts}"
    return 1
  fi

}

emit_current() {
  local row
  while IFS= read -r row; do
    if [[ -n "${row}" ]]; then
      printf '%s\t%s\n' "${sample_ts}" "${row}"
    fi
  done < "${current_file}"
}

zones_ready() {
  [[ -s "${current_file}" ]] \
    && ! cut -f 4 "${current_file}" | grep -Fqx -- "-"
}

topology_ready() {
  "${JQ_BIN}" -e '
    ([.items[] | select((.metadata.labels.app // "") == "kms-core")] | length) >= 13
    and any(
      .items[];
      ((.metadata.labels.test // "") | contains("-rate-"))
    )
  ' "${pods_file}" >/dev/null
}

for attempt in {1..180}; do
  if sample_once && zones_ready && topology_ready; then
    emit_current
    exit 0
  fi
  if [[ "${attempt}" -lt 180 ]]; then
    sleep "${INTERVAL}"
  fi
done

printf '# sampler_error complete_topology_not_ready_after_180_attempts\n'
exit 1

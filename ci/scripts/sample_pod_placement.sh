#!/usr/bin/env bash
# Record each KMS core and perf-workflow pod's node placement once. The workflow
# runs this continuously because rate-test pods may be gone before post-run collection.
# A headless Service over the ENA probes exposes node names and zones through a
# namespaced EndpointSlice, avoiding cluster-scoped Node API permissions.
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-5}"
MODE="${3:-}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
JQ_BIN="${JQ_BIN:-jq}"

if [[ -n "${MODE}" && "${MODE}" != "--once" ]]; then
  echo "usage: $0 [namespace] [interval-seconds] [--once]" >&2
  exit 2
fi

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT

seen_file="${tmp_root}/seen.tsv"
current_file="${tmp_root}/current.tsv"
sample_ts=""
touch "${seen_file}"
touch "${current_file}"

printf '# sampler_start=%s namespace=%s interval=%ss\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NS}" "${INTERVAL}"
printf 'timestamp\tpod\tworkflow_node\tnode\tzone\tinstance_type\tnodepool\n'

single_line() {
  tr '\n' ' ' < "$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

sample_once() {
  local pods_file slices_file pods_error slices_error
  sample_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pods_file="${tmp_root}/pods.json"
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
    if [[ -n "${row}" ]] && ! grep -Fqx -- "${row}" "${seen_file}"; then
      printf '%s\t%s\n' "${sample_ts}" "${row}"
      printf '%s\n' "${row}" >> "${seen_file}"
    fi
  done < "${current_file}"
}

zones_ready() {
  [[ -s "${current_file}" ]] \
    && ! cut -f 4 "${current_file}" | grep -Fqx -- "-"
}

if [[ "${MODE}" == "--once" ]]; then
  for attempt in {1..30}; do
    if sample_once && zones_ready; then
      emit_current
      exit 0
    fi
    if [[ "${attempt}" -lt 30 ]]; then
      sleep "${INTERVAL}"
    fi
  done
  emit_current
  printf '# sampler_error zones_not_ready_after_30_attempts\n'
  exit 1
fi

while true; do
  if sample_once; then
    emit_current
  fi
  sleep "${INTERVAL}"
done

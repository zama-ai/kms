#!/usr/bin/env bash
# Record each KMS core and perf-workflow pod's node placement once. The workflow
# runs this continuously because rate-test pods may be gone before post-run collection.
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-5}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
JQ_BIN="${JQ_BIN:-jq}"

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT

seen_file="${tmp_root}/seen.tsv"
touch "${seen_file}"

printf '# sampler_start=%s namespace=%s interval=%ss\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NS}" "${INTERVAL}"
printf 'timestamp\tpod\tworkflow_node\tnode\tzone\tinstance_type\tnodepool\n'

single_line() {
  tr '\n' ' ' < "$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

sample_once() {
  local ts pods_file nodes_file pods_error nodes_error current_file
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pods_file="${tmp_root}/pods.json"
  nodes_file="${tmp_root}/nodes.json"
  pods_error="${tmp_root}/pods-error"
  nodes_error="${tmp_root}/nodes-error"
  current_file="${tmp_root}/current.tsv"

  if ! "${KUBECTL_BIN}" get pods -n "${NS}" -o json \
    > "${pods_file}" 2> "${pods_error}"; then
    printf '# %s sampler_error pod_discovery="%s"\n' \
      "${ts}" "$(single_line "${pods_error}")"
    return
  fi
  if ! "${KUBECTL_BIN}" get nodes -o json \
    > "${nodes_file}" 2> "${nodes_error}"; then
    printf '# %s sampler_error node_discovery="%s"\n' \
      "${ts}" "$(single_line "${nodes_error}")"
    return
  fi

  # The single-quoted program is jq syntax; none of its `$` variables are shell variables.
  # shellcheck disable=SC2016
  "${JQ_BIN}" -r --slurpfile nodes "${nodes_file}" '
    def node_for($name):
      first($nodes[0].items[] | select(.metadata.name == $name)) //
      {"metadata":{"labels":{}}};

    .items[]
    | select((.spec.nodeName // "") != "")
    | select(
        (.metadata.labels.app // "") == "kms-core"
        or ((.metadata.labels["workflows.argoproj.io/workflow"] // "") | startswith("kms-perf-"))
      )
    | . as $pod
    | node_for($pod.spec.nodeName) as $node
    | [
        ($pod.metadata.name // "-"),
        ($pod.metadata.labels["workflows.argoproj.io/node-name"] // "-"),
        ($pod.spec.nodeName // "-"),
        ($node.metadata.labels["topology.kubernetes.io/zone"] //
          $node.metadata.labels["failure-domain.beta.kubernetes.io/zone"] // "-"),
        ($node.metadata.labels["node.kubernetes.io/instance-type"] // "-"),
        ($node.metadata.labels["karpenter.sh/nodepool"] // "-")
      ]
    | @tsv
  ' "${pods_file}" | sort -u > "${current_file}"

  local row
  while IFS= read -r row; do
    if [[ -n "${row}" ]] && ! grep -Fqx -- "${row}" "${seen_file}"; then
      printf '%s\t%s\n' "${ts}" "${row}"
      printf '%s\n' "${row}" >> "${seen_file}"
    fi
  done < "${current_file}"
}

while true; do
  sample_once
  sleep "${INTERVAL}"
done

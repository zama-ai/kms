{{- define "kmsCoreName" -}}
{{- $kmsCoreNameDefault := printf "%s-%s" .Release.Name "core" }}
{{- default $kmsCoreNameDefault .Values.kmsCore.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsCoreClientName" -}}
{{- $kmsCoreClientNameDefault := printf "%s-%s" .Release.Name "client" }}
{{- default $kmsCoreClientNameDefault .Values.kmsCoreClient.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsCoreClientTestingName" -}}
{{- $kmsCoreClientNameDefault := printf "%s-%s" .Release.Name "client-testing" }}
{{- default $kmsCoreClientNameDefault .Values.kmsCoreClientTesting.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsCoreAddress" -}}
{{- $kmsCoreAddressDefault := print "" -}}
{{- if .Values.mtls.enabled -}}
{{ printf "http://%s_%s_svc_%d.mesh:80" (include "kmsCoreName" .) .Release.Namespace (int .Values.kmsCore.ports.client) }}
{{- else -}}
{{ printf "http://%s:%d" (include "kmsCoreName" .) (int .Values.kmsCore.ports.client) }}
{{- end -}}
{{ default $kmsCoreAddressDefault .Values.kmsCore.addressOverride }}
{{- end -}}

{{- define "kmsCoreMode" -}}
{{- if .Values.kmsCore.thresholdMode.enabled -}}
threshold
{{- else -}}
centralized
{{- end -}}
{{- end -}}

{{- define "kmsPeersStartID" -}}
{{ default 1 .Values.kmsPeers.id }}
{{- end -}}

{{- define "kmsNetworkTunnelQueueCount" -}}
{{- $configured := .Values.kmsCore.nitroEnclave.networkTunnel.queueCount -}}
{{- if and $configured (gt (int $configured) 0) -}}
{{- int $configured -}}
{{- else if .Values.kmsCore.thresholdMode.enabled -}}
{{- $partyCount := int .Values.kmsPeers.count -}}
{{- if .Values.kmsCore.thresholdMode.peersList -}}
{{- $partyCount = len .Values.kmsCore.thresholdMode.peersList -}}
{{- end -}}
{{- $hotFlows := 0 -}}
{{- if gt $partyCount 1 -}}
{{- $hotFlows = mul 2 (sub $partyCount 1) -}}
{{- end -}}
{{- if le $hotFlows 8 -}}8
{{- else if le $hotFlows 16 -}}16
{{- else if le $hotFlows 32 -}}32
{{- else if le $hotFlows 64 -}}64
{{- else if le $hotFlows 128 -}}128
{{- else -}}256
{{- end -}}
{{- else -}}8
{{- end -}}
{{- end -}}

{{- define "kmsNetworkTunnelTokioWorkerThreads" -}}
{{- $configured := .Values.kmsCore.nitroEnclave.networkTunnel.tokioWorkerThreads -}}
{{- if and $configured (gt (int $configured) 0) -}}
{{- int $configured -}}
{{- else -}}
{{- $queueCount := include "kmsNetworkTunnelQueueCount" . | int -}}
{{- if le $queueCount 16 -}}4
{{- else -}}8
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Secondary co-located enclave helpers */}}

{{- define "kmsCoreSecondaryName" -}}
{{ include "kmsCoreName" . }}-dkg
{{- end -}}

{{- define "kmsSecondaryImageName" -}}
{{ default .Values.kmsCore.image.name .Values.kmsCore.secondaryEnclave.image.name }}
{{- end -}}

{{- define "kmsSecondaryImageTag" -}}
{{ default .Values.kmsCore.image.tag .Values.kmsCore.secondaryEnclave.image.tag }}
{{- end -}}

{{- define "kmsSecondaryImagePullPolicy" -}}
{{ default .Values.kmsCore.image.pullPolicy .Values.kmsCore.secondaryEnclave.image.pullPolicy }}
{{- end -}}

{{/* The CID that maps to the unshifted parent vsock ports (4000/3000/2100).
     MUST match CID_BASE baked into init_enclave.sh in the EIF, and the primary
     kmsCore.nitroEnclave.cid must equal it so the primary keeps 4000/3000/2100. */}}
{{- define "kmsEnclaveCidBase" -}}20{{- end -}}

{{/* Parent-side vsock port offset for the secondary enclave, relative to the
     CID base. init_enclave.sh applies the same offset (cid - CID_BASE) so a
     single EIF backs both enclaves without vsock collisions on the host. */}}
{{- define "kmsSecondaryEnclavePortOffset" -}}
{{- sub (int .Values.kmsCore.secondaryEnclave.nitroEnclave.cid) (include "kmsEnclaveCidBase" . | int) -}}
{{- end -}}

{{- define "kmsSecondaryConfigPort" -}}
{{- add 4000 (include "kmsSecondaryEnclavePortOffset" . | int) -}}
{{- end -}}

{{- define "kmsSecondaryLoggerPort" -}}
{{- add 3000 (include "kmsSecondaryEnclavePortOffset" . | int) -}}
{{- end -}}

{{- define "kmsSecondaryTunnelVsockPort" -}}
{{- add 2100 (include "kmsSecondaryEnclavePortOffset" . | int) -}}
{{- end -}}

{{- define "kmsSecondaryNetworkTunnelQueueCount" -}}
{{- $configured := .Values.kmsCore.secondaryEnclave.nitroEnclave.networkTunnel.queueCount -}}
{{- if and $configured (gt (int $configured) 0) -}}
{{- int $configured -}}
{{- else -}}
{{- $partyCount := len .Values.kmsCore.secondaryEnclave.thresholdMode.peersList -}}
{{- $hotFlows := 0 -}}
{{- if gt $partyCount 1 -}}
{{- $hotFlows = mul 2 (sub $partyCount 1) -}}
{{- end -}}
{{- if le $hotFlows 8 -}}8
{{- else if le $hotFlows 16 -}}16
{{- else if le $hotFlows 32 -}}32
{{- else if le $hotFlows 64 -}}64
{{- else if le $hotFlows 128 -}}128
{{- else -}}256
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kmsSecondaryNetworkTunnelTokioWorkerThreads" -}}
{{- $configured := .Values.kmsCore.secondaryEnclave.nitroEnclave.networkTunnel.tokioWorkerThreads -}}
{{- if and $configured (gt (int $configured) 0) -}}
{{- int $configured -}}
{{- else -}}
{{- $queueCount := include "kmsSecondaryNetworkTunnelQueueCount" . | int -}}
{{- if le $queueCount 16 -}}4
{{- else -}}8
{{- end -}}
{{- end -}}
{{- end -}}

{{/* takes a (dict "name" string
     	     	   "image" (dict "name" string "tag" string)
     	     	   "from" string
		      "to" string */}}
{{- define "socatContainer" -}}
name: {{ .name }}
image: {{ .image.name }}:{{ .image.tag }}
imagePullPolicy: {{ .image.pullPolicy }}
restartPolicy: Always
command:
  - socat
args:
  - -d0
  - {{ .from }}
  - {{ .to }}
{{- end -}}

{{/* takes a (dict "name" string
     	     	   "image" (dict "name" string "tag" string)
                   "vsockPort" int
		           "to" string) */}}
{{- define "proxyFromEnclave" -}}
{{- include "socatContainer"
      (dict "name" .name
            "image" .image
            "from" (printf "VSOCK-LISTEN:%d,fork,reuseaddr" (int .vsockPort))
	      "to" .to) }}
{{- end -}}

{{/* takes a (dict "image" kms-core-image-values
                     "networkTunnel" nitro-network-tunnel-values
                     "ingressPorts" list-of-tcp-ports
                     "queueCount" int
                     "workerThreads" int)
        and renders the pod-local parent-side TUN bridge and DNS proxy used for
       enclave egress as a native Kubernetes sidecar. When ingressPorts is not
       empty, TCP ingress is DNATed into the enclave over the TUN. The tunnel
       VSOCK port defaults to 2100 (primary) and can be overridden via the
       "vsockPort" key for co-located enclaves; it must match the CID-derived
       NETWORK_TUNNEL_PORT computed by init_enclave.sh. */}}
{{- define "enclaveNetworkTunnelContainer" -}}
name: enclave-network-tunnel{{ .nameSuffix }}
image: {{ .image.name }}:{{ .image.tag }}
imagePullPolicy: {{ .image.pullPolicy }}
{{- if gt (len .ingressPorts) 0 }}
env:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
{{- end }}
securityContext:
  allowPrivilegeEscalation: true
  privileged: true
  runAsUser: 0
restartPolicy: Always
command:
  - /bin/sh
args:
  - -c
  - |
    set -eu
    TUN_IF={{ .networkTunnel.interfaceName | quote }}
    TUN_ADDR={{ .networkTunnel.parentAddress | quote }}
    TUN_HOST="${TUN_ADDR%/*}"
    ENCLAVE_TUN_ADDR={{ .networkTunnel.enclaveAddress | quote }}
    case "$ENCLAVE_TUN_ADDR" in
      */*) ;;
      *)
        echo "enclave-network-tunnel: enclave tunnel address missing CIDR prefix: $ENCLAVE_TUN_ADDR" >&2
        exit 1
        ;;
    esac
    ENCLAVE_TUN_IP="${ENCLAVE_TUN_ADDR%/*}"
    TUN_SUBNET={{ .networkTunnel.subnet | quote }}
    VSOCK_PORT={{ .vsockPort | default 2100 | quote }}
    QUEUE_COUNT={{ .queueCount | quote }}
    TOKIO_WORKER_THREADS={{ .workerThreads | quote }}
    UPSTREAM_DNS=""
    TUNNEL_PID=""
    DNSPROXY_PID=""

    while read -r key value _; do
      if [ "$key" = "nameserver" ]; then
        UPSTREAM_DNS="$value"
        break
      fi
    done < /etc/resolv.conf

    if [ -z "$UPSTREAM_DNS" ]; then
      echo "enclave-network-tunnel: cannot determine upstream nameserver from /etc/resolv.conf" >&2
      exit 1
    fi

    {{- if gt (len .ingressPorts) 0 }}
    if [ -z "${POD_IP:-}" ]; then
      echo "enclave-network-tunnel: POD_IP is not set" >&2
      exit 1
    fi
    {{- end }}

    cleanup() {
      if [ -n "$TUNNEL_PID" ]; then
        kill "$TUNNEL_PID" 2>/dev/null || true
      fi
      if [ -n "$DNSPROXY_PID" ]; then
        kill "$DNSPROXY_PID" 2>/dev/null || true
      fi
    }

    trap cleanup EXIT INT TERM

    sysctl -w net.ipv4.ip_forward=1 || echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -C POSTROUTING -s "$TUN_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "$TUN_SUBNET" -o eth0 -j MASQUERADE
    iptables -C FORWARD -i "$TUN_IF" -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -i "$TUN_IF" -j ACCEPT
    iptables -C FORWARD -o "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -o "$TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    echo "enclave-network-tunnel: starting parent-side TUN bridge on $TUN_HOST via $UPSTREAM_DNS"
    vsocktun parent \
      --tun-name "$TUN_IF" \
      --tun-address "$TUN_ADDR" \
      --enclave-address "$ENCLAVE_TUN_ADDR" \
      --vsock-port "$VSOCK_PORT" \
      --queues "$QUEUE_COUNT" \
      --tokio-worker-threads "$TOKIO_WORKER_THREADS" &
    TUNNEL_PID=$!

    for _ in $(seq 1 30); do
      if ifconfig "$TUN_IF" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    if ! ifconfig "$TUN_IF" >/dev/null 2>&1; then
      echo "enclave-network-tunnel: tunnel interface $TUN_IF did not come up" >&2
      exit 1
    fi

    {{- if gt (len .ingressPorts) 0 }}
    add_ingress_dnat() {
      port="$1"
      iptables -t nat -C PREROUTING -i eth0 -d "$POD_IP" -p tcp --dport "$port" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$port" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i eth0 -d "$POD_IP" -p tcp --dport "$port" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$port"
      iptables -C FORWARD -i eth0 -o "$TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$port" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i eth0 -o "$TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$port" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
    }

    {{- range .ingressPorts }}
    add_ingress_dnat {{ . | quote }}
    {{- end }}
    {{- end }}

    dnsproxy -l "$TUN_HOST" -u "$UPSTREAM_DNS" &
    DNSPROXY_PID=$!

    while kill -0 "$TUNNEL_PID" 2>/dev/null && kill -0 "$DNSPROXY_PID" 2>/dev/null; do
      sleep 1
    done

    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
      TUNNEL_STATUS=0
      wait "$TUNNEL_PID" || TUNNEL_STATUS=$?
      exit "$TUNNEL_STATUS"
    fi

    DNSPROXY_STATUS=0
    wait "$DNSPROXY_PID" || DNSPROXY_STATUS=$?
    exit "$DNSPROXY_STATUS"
{{- end -}}

{{- define "kmsInitJobName" -}}
{{- $kmsCoreNameDefault := printf "%s-%s" .Release.Name "threshold-init" }}
{{- default $kmsCoreNameDefault .Values.kmsInit.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsGenKeyJobName" -}}
{{- $kmsCoreNameDefault := printf "%s-%s" .Release.Name "gen-key" }}
{{- default $kmsCoreNameDefault .Values.kmsGenKeys.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsGenCertAndKeysJobName" -}}
{{- $kmsCoreNameDefault := printf "%s-%s" .Release.Name "gen-cert-and-keys" }}
{{- default $kmsCoreNameDefault .Values.kmsGenCertAndKeys.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmsCoreInitEnvVars" -}}
export AWS_REGION="${AWS_REGION:={{ .Values.kmsCore.aws.region }}}"
export AWS_ROLE_ARN="${AWS_ROLE_ARN:={{ .Values.kmsCore.aws.roleArn }}}"
{{- if .Values.kmsCore.publicVault.s3.enabled }}
export KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET="${KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET:={{ .Values.kmsCore.publicVault.s3.bucket }}}"
export KMS_CORE__PUBLIC_VAULT__STORAGE__S3__PREFIX="${KMS_CORE__PUBLIC_VAULT__STORAGE__S3__PREFIX:={{ .Values.kmsCore.publicVault.s3.prefix }}}"
{{- end }}
{{- if .Values.kmsCore.privateVault.s3.enabled }}
export KMS_CORE__PRIVATE_VAULT__STORAGE__S3__BUCKET="${KMS_CORE__PRIVATE_VAULT__STORAGE__S3__BUCKET:={{ .Values.kmsCore.privateVault.s3.bucket }}}"
export KMS_CORE__PRIVATE_VAULT__STORAGE__S3__PREFIX="${KMS_CORE__PRIVATE_VAULT__STORAGE__S3__PREFIX:={{ .Values.kmsCore.privateVault.s3.prefix }}}"
{{- end }}
{{- if .Values.kmsCore.backupVault.s3.enabled }}
export KMS_CORE__BACKUP_VAULT__STORAGE__S3__BUCKET="${KMS_CORE__BACKUP_VAULT__STORAGE__S3__BUCKET:={{ .Values.kmsCore.backupVault.s3.bucket }}}"
export KMS_CORE__BACKUP_VAULT__STORAGE__S3__PREFIX="${KMS_CORE__BACKUP_VAULT__STORAGE__S3__PREFIX:={{ .Values.kmsCore.backupVault.s3.prefix }}}"
{{- end }}
{{- if .Values.kmsCore.nitroEnclave.enabled }}
export KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID="${KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID:={{ .Values.kmsCore.privateVault.awskms.rootKeyId }}}"
export KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC="${KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC:={{ .Values.kmsCore.privateVault.awskms.rootKeySpec }}}"
{{- if .Values.kmsCore.backupVault.awskms.enabled }}
export KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID="${KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID:={{ .Values.kmsCore.backupVault.awskms.rootKeyId }}}"
export KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC="${KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC:={{ .Values.kmsCore.backupVault.awskms.rootKeySpec }}}"
{{- end }}
{{- end }}
{{- if $.Values.kmsCore.thresholdMode.tls.enabled }}
# Fetch CA certificates for all peers (needed for peer verification)
# In minio/localstack context: CORE_CLIENT__S3_ENDPOINT is just the endpoint, need to add bucket
# In AWS context: CORE_CLIENT__S3_ENDPOINT already contains the bucket path
{{- if $.Values.minio.enabled }}
S3_BASE_URL="${CORE_CLIENT__S3_ENDPOINT}/{{ .Values.kmsCore.publicVault.s3.bucket }}"
{{- else }}
S3_BASE_URL="${CORE_CLIENT__S3_ENDPOINT}"
{{- end }}
echo "Fetching TLS certificates from S3 base URL: ${S3_BASE_URL}"
{{- range .Values.kmsCore.thresholdMode.peersList }}
{{- if or $.Values.minio.enabled (not $.Values.kmsCore.nitroEnclave.enabled) }}
# For minio/localstack or non-enclave threshold: use direct path to cert.pem
CERT_PATH="PUB-p{{ .id }}/CACert/cert.pem"
echo "Fetching CA cert for party {{ .id }} from: ${S3_BASE_URL}/${CERT_PATH}"
# Retry logic: wait for certificate to appear (for parallel deployments)
MAX_RETRIES=30
RETRY_COUNT=0
RETRY_DELAY=2
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s -f -o ./ca_pem_{{ .id }} "${S3_BASE_URL}/${CERT_PATH}"; then
    export KMS_CA_PEM_{{ .id }}="\"\"\"$(cat ./ca_pem_{{ .id }})\"\"\""
    echo "Successfully fetched CA cert for party {{ .id }}"
    break
  else
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      echo "Certificate not found yet, retry $RETRY_COUNT/$MAX_RETRIES in ${RETRY_DELAY}s..."
      sleep $RETRY_DELAY
    else
      echo "WARNING: No CA cert found for party {{ .id }} at ${CERT_PATH} after $MAX_RETRIES retries"
    fi
  fi
done
{{- else }}
# For AWS enclave: use S3 list to discover the cert path
echo "Looking for CA cert for party {{ .id }} at: ${S3_BASE_URL}?list-type=2&prefix=PUB-p{{ .id }}/CACert/"
BUCKET_PATH_{{ .id }}=$(curl -s "${S3_BASE_URL}?list-type=2&prefix=PUB-p{{ .id }}/CACert/" | grep -o "<Key>[^<]*</Key>" | sed "s/<Key>//;s/<\/Key>//")
echo "Found bucket path: ${BUCKET_PATH_{{ .id }}}"
if [ -n "${BUCKET_PATH_{{ .id }}}" ]; then
  curl -s -o ./ca_pem_{{ .id }} "${S3_BASE_URL}/${BUCKET_PATH_{{ .id }}}"
  export KMS_CA_PEM_{{ .id }}="\"\"\"$(cat ./ca_pem_{{ .id }})\"\"\""
  echo "Fetched CA cert for party {{ .id }}"
else
  echo "WARNING: No CA cert found for party {{ .id }}"
fi
{{- end }}
{{- end }}
# Fetch private key only for this party (party {{ .Values.kmsPeers.id }})
{{- if or $.Values.minio.enabled (not $.Values.kmsCore.nitroEnclave.enabled) }}
# For minio/localstack or non-enclave threshold: use direct path to key.pem
KEY_PATH="PUB-p{{ .Values.kmsPeers.id }}/PrivateKey/key.pem"
echo "Fetching private key from: ${S3_BASE_URL}/${KEY_PATH}"
# Retry logic: wait for private key to appear (for parallel deployments)
MAX_RETRIES=30
RETRY_COUNT=0
RETRY_DELAY=2
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s -f -o ./key_pem "${S3_BASE_URL}/${KEY_PATH}"; then
    export KMS_KEY_PEM_{{ .Values.kmsPeers.id }}="\"\"\"$(cat ./key_pem)\"\"\""
    echo "Successfully fetched private key for party {{ .Values.kmsPeers.id }}"
    break
  else
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      echo "Private key not found yet, retry $RETRY_COUNT/$MAX_RETRIES in ${RETRY_DELAY}s..."
      sleep $RETRY_DELAY
    else
      echo "WARNING: No private key found for party {{ .Values.kmsPeers.id }} at ${KEY_PATH} after $MAX_RETRIES retries"
    fi
  fi
done
{{- else }}
# For AWS enclave: use S3 list to discover the key path
echo "Looking for private key at: ${S3_BASE_URL}?list-type=2&prefix=PUB-p{{ .Values.kmsPeers.id }}/PrivateKey/"
KEY_BUCKET_PATH=$(curl -s "${S3_BASE_URL}?list-type=2&prefix=PUB-p{{ .Values.kmsPeers.id }}/PrivateKey/" | grep -o "<Key>[^<]*</Key>" | sed "s/<Key>//;s/<\/Key>//" || true)
echo "Found key bucket path: ${KEY_BUCKET_PATH}"
if [ -n "${KEY_BUCKET_PATH}" ]; then
  curl -s -o ./key_pem "${S3_BASE_URL}/${KEY_BUCKET_PATH}"
  export KMS_KEY_PEM_{{ .Values.kmsPeers.id }}="\"\"\"$(cat ./key_pem)\"\"\""
  echo "Fetched private key for party {{ .Values.kmsPeers.id }}"
else
  echo "WARNING: No private key found for party {{ .Values.kmsPeers.id }}"
fi
{{- end }}
echo "### BEGIN - env ###"
env
echo "### END - env ###"
{{- end }}
{{- end -}}

{{/* Fetch CA certificates for the SECONDARY (co-located shard) network peers.
     Mirrors the primary CA fetch in kmsCoreInitEnvVars, but reads from the
     secondary public-vault prefix (PUB-dkg-p<id>) and exports KMS_CA_PEM_DKG_<id>
     so kms-server-dkg.toml can pin each network-DKG peer's CA. The secondary is
     enclave-only, so this covers the minio and AWS-enclave S3 layouts. */}}
{{- define "kmsCoreSecondaryCaCerts" -}}
{{- $sec := .Values.kmsCore.secondaryEnclave -}}
{{- if and .Values.kmsCore.thresholdMode.tls.enabled $sec.enabled $sec.thresholdMode.peersList }}
# Fetch CA certificates for all SECONDARY-network (DKG) peers
{{- if $.Values.minio.enabled }}
S3_BASE_URL_DKG="${CORE_CLIENT__S3_ENDPOINT}/{{ .Values.kmsCore.publicVault.s3.bucket }}"
{{- else }}
S3_BASE_URL_DKG="${CORE_CLIENT__S3_ENDPOINT}"
{{- end }}
echo "Fetching network-DKG TLS certificates from S3 base URL: ${S3_BASE_URL_DKG}"
{{- range $sec.thresholdMode.peersList }}
{{- if $.Values.minio.enabled }}
CERT_PATH_DKG="PUB-dkg-p{{ .id }}/CACert/cert.pem"
echo "Fetching DKG CA cert for party {{ .id }} from: ${S3_BASE_URL_DKG}/${CERT_PATH_DKG}"
MAX_RETRIES=30
RETRY_COUNT=0
RETRY_DELAY=2
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s -f -o ./ca_pem_dkg_{{ .id }} "${S3_BASE_URL_DKG}/${CERT_PATH_DKG}"; then
    export KMS_CA_PEM_DKG_{{ .id }}="\"\"\"$(cat ./ca_pem_dkg_{{ .id }})\"\"\""
    echo "Successfully fetched DKG CA cert for party {{ .id }}"
    break
  else
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      echo "DKG certificate not found yet, retry $RETRY_COUNT/$MAX_RETRIES in ${RETRY_DELAY}s..."
      sleep $RETRY_DELAY
    else
      echo "WARNING: No DKG CA cert found for party {{ .id }} at ${CERT_PATH_DKG} after $MAX_RETRIES retries"
    fi
  fi
done
{{- else }}
echo "Looking for DKG CA cert for party {{ .id }} at: ${S3_BASE_URL_DKG}?list-type=2&prefix=PUB-dkg-p{{ .id }}/CACert/"
BUCKET_PATH_DKG_{{ .id }}=$(curl -s "${S3_BASE_URL_DKG}?list-type=2&prefix=PUB-dkg-p{{ .id }}/CACert/" | grep -o "<Key>[^<]*</Key>" | sed "s/<Key>//;s/<\/Key>//")
echo "Found DKG bucket path: ${BUCKET_PATH_DKG_{{ .id }}}"
if [ -n "${BUCKET_PATH_DKG_{{ .id }}}" ]; then
  curl -s -o ./ca_pem_dkg_{{ .id }} "${S3_BASE_URL_DKG}/${BUCKET_PATH_DKG_{{ .id }}}"
  export KMS_CA_PEM_DKG_{{ .id }}="\"\"\"$(cat ./ca_pem_dkg_{{ .id }})\"\"\""
  echo "Fetched DKG CA cert for party {{ .id }}"
else
  echo "WARNING: No DKG CA cert found for party {{ .id }}"
fi
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* ============================================================================
     Per-network ConfigMap document templates.

     Each template takes a single dict describing one kms-core network so the
     primary and the co-located secondary (shard) network render from the same
     source. See kms-core-configmap.yaml for how the dicts are built. The output
     is consumed as TOML via envsubst, so leading whitespace / blank lines are
     insignificant.
     ============================================================================ */}}

{{/* vaults.toml body.
     dict keys:
       ctx            root context ($) for shared publicVault/privateVault/backupVault values
       publicPrefix   string to emit as the public-vault S3 prefix ("" = omit)
       privatePrefix  string to emit as the private-vault S3 prefix ("" = omit)
       keychainAwsKms bool, whether to emit [private_vault.keychain.aws_kms] */}}
{{- define "kms-core.vaultsToml" -}}
{{- $ctx := .ctx -}}
{{- if $ctx.Values.kmsCore.publicVault.s3.enabled }}
[public_vault.storage.s3]
bucket = "${KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET}"
{{- if .publicPrefix }}
prefix = "{{ .publicPrefix }}"
{{- end }}
{{- else }}
[public_vault.storage.file]
path = "/keys"
{{- end }}
{{- if $ctx.Values.kmsCore.privateVault.s3.enabled }}
[private_vault.storage.s3]
bucket = "${KMS_CORE__PRIVATE_VAULT__STORAGE__S3__BUCKET}"
{{- if .privatePrefix }}
prefix = "{{ .privatePrefix }}"
{{- end }}
{{- else }}
[private_vault.storage.file]
path = "/keys"
{{- end }}
{{- if .keychainAwsKms }}
[private_vault.keychain.aws_kms]
root_key_id = "${KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID}"
root_key_spec = "${KMS_CORE__PRIVATE_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC}"
{{- end }}
{{- if $ctx.Values.kmsCore.backupVault.s3.enabled }}
[backup_vault.storage.s3]
bucket = "${KMS_CORE__BACKUP_VAULT__STORAGE__S3__BUCKET}"
{{- if $ctx.Values.kmsCore.backupVault.s3.prefix }}
prefix = "${KMS_CORE__BACKUP_VAULT__STORAGE__S3__PREFIX}"
{{- end }}
{{- end }}
{{- if $ctx.Values.kmsCore.backupVault.awskms.enabled }}
[backup_vault.keychain.aws_kms]
root_key_id = "${KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_ID}"
root_key_spec = "${KMS_CORE__BACKUP_VAULT__KEYCHAIN__AWS_KMS__ROOT_KEY_SPEC}"
{{- else }}
{{- if $ctx.Values.kmsCore.custodianBackup }}
[backup_vault.keychain.secret_sharing]
{{- end }}
{{- end }}
{{- end -}}

{{/* kms-gen-keys.toml body.
     dict keys:
       ctx                  root context ($) (used for addressOverride / kmsCoreName)
       thresholdEnabled     bool, whether to emit [threshold]
       myId                 string emitted as my_id
       tlsSubjectId         value appended to the tls_subject host
       enclaveBootstrap     bool, whether to emit [enclave_bootstrap]
       webIdentityTokenPort int */}}
{{- define "kms-core.genKeysToml" -}}
{{- $ctx := .ctx -}}
[keygen]
enabled = true
{{- if .thresholdEnabled }}
[threshold]
my_id = "{{ .myId }}"
{{- if $ctx.Values.kmsCore.addressOverride }}
tls_subject = "{{ $ctx.Values.kmsCore.addressOverride }}-{{ .tlsSubjectId }}"
{{- else }}
tls_subject = "{{ include "kmsCoreName" $ctx }}-{{ .tlsSubjectId }}"
{{- end }}
{{- end }}
{{- if .enclaveBootstrap }}
[enclave_bootstrap]
web_identity_token_port = {{ int .webIdentityTokenPort }}
{{- end }}
{{- end -}}

{{/* enclave.json body.
     dict keys: cpuCount, memoryGiB, cid, eifPath */}}
{{- define "kms-core.enclaveJson" -}}
{
  "cpu_count": {{ int .cpuCount }},
  "memory_mib": {{ mulf 1024 (int .memoryGiB) }},
  "enclave_cid": {{ int .cid }},
  "eif_path": {{ .eifPath | quote }}
}
{{- end -}}

{{/* kms-server.toml body (the big one).
     dict keys:
       ctx                  root context ($) for shared tls / rateLimiter / redis / tracing / kmsPeers / resources
       net                  threshold value subtree (.Values.kmsCore or .Values.kmsCore.secondaryEnclave)
       clientPort           [service] listen_port
       peerPort             [threshold] listen_port
       metricsPort          telemetry metrics port
       myId                 string emitted as my_id
       serviceName          telemetry tracing_service_name
       caPemPrefix          env-var prefix for per-peer CA pinning (KMS_CA_PEM_ or KMS_CA_PEM_DKG_)
       thresholdEnabled     bool, whether to emit the [threshold] section
       enclaveBootstrap     bool, whether to emit [enclave_bootstrap]
       webIdentityTokenPort int
       tlsMode              "auto" or "manual" (only used when tls.enabled)
       hasAutoPeersFallback bool, whether to auto-generate peers when peersList is empty */}}
{{- define "kms-core.serverToml" -}}
{{- $ctx := .ctx -}}
{{- $net := .net -}}
{{- $tls := $ctx.Values.kmsCore.thresholdMode.tls -}}
[service]
listen_address = "0.0.0.0"
listen_port = {{ int .clientPort }}
timeout_secs = {{ int $ctx.Values.kmsCore.resources.limits.grpcTimeout }}
grpc_max_message_size = {{ int $ctx.Values.kmsCore.resources.limits.grpcMaxMessageSize }}
{{- if .enclaveBootstrap }}

[enclave_bootstrap]
web_identity_token_port = {{ int .webIdentityTokenPort }}
{{- end }}
{{- if .thresholdEnabled }}

[threshold]
listen_address = "0.0.0.0"
listen_port = {{ int .peerPort }}

my_id = "{{ .myId }}"

# Threshold is the number of corruptions that the protocol handles.
threshold = {{ int $net.thresholdMode.thresholdValue }}
dec_capacity = {{ int $net.thresholdMode.decCapacity }}
min_dec_cache = {{ int $net.thresholdMode.minDecCache }}
num_sessions_preproc = {{ int $net.thresholdMode.numSessionsPreproc }}
decryption_mode = {{ $net.thresholdMode.decryptionMode | quote }}

[threshold.core_to_core_net]
message_limit = 70
multiplier = {{ float64 $net.thresholdMode.multiplier }}
max_interval = {{ int $net.thresholdMode.maxInterval }}
max_elapsed_time = {{ int $net.thresholdMode.maxElapsedTime }}
network_timeout = {{ int $net.thresholdMode.networkTimeout }}
network_timeout_bk = 300
network_timeout_bk_sns = 1200
max_en_decode_message_size = 2147483648
initial_interval_ms = {{ int $net.thresholdMode.initialIntervalMs }}
session_update_interval_secs = 60
session_cleanup_interval_secs = 86400
discard_inactive_sessions_interval = 900
max_waiting_time_for_message_queue = 60
max_opened_inactive_sessions_per_party = {{ int $net.thresholdMode.maxOpenedInactiveSessionsPerParty }}
{{- if $tls.enabled }}
{{- if eq .tlsMode "auto" }}

[threshold.tls.auto]
{{- if $tls.ignoreAwsCaChain }}
ignore_aws_ca_chain = true
{{- else }}
ignore_aws_ca_chain = false
{{- end }}
{{- if $tls.attestPrivateVaultRootKey }}
attest_private_vault_root_key = true
{{- else }}
attest_private_vault_root_key = false
{{- end }}
{{- if $tls.trustedReleases }}
{{- range $tls.trustedReleases }}
[[threshold.tls.auto.trusted_releases]]
pcr0 = {{ .pcr0 | quote }}
pcr1 = {{ .pcr1 | quote }}
pcr2 = {{ .pcr2 | quote }}
{{- end }}
{{- end }}
{{- else }}

[threshold.tls.manual]
{{- if (default dict $tls.certificate).path }}
cert.path = {{ $tls.certificate.path | quote }}
{{- else }}
cert.pem = ${KMS_CA_PEM_{{ $ctx.Values.kmsPeers.id }}}
{{- end }}
{{- if (default dict $tls.privateKey).path }}
key.path = {{ $tls.privateKey.path | quote }}
{{- else }}
key.pem = ${KMS_KEY_PEM_{{ $ctx.Values.kmsPeers.id }}}
{{- end }}
{{- end }}
{{- end }}
{{- if $net.thresholdMode.peersList }}
{{- range $net.thresholdMode.peersList }}

[[threshold.peers]]
party_id = {{ int .id }}
mpc_identity = {{ .host | quote }}
address = {{ .host | quote }}
port = {{ int .port }}
{{- if $tls.enabled }}
{{- if (default dict $tls.ca_certificate).path }}
tls_cert.path = {{ $tls.ca_certificate.path | quote }}
{{- else }}
tls_cert.pem = {{ printf "${%s%d}" $.caPemPrefix (int .id) }}
{{- end }}
{{- end }}
{{- end }}
{{- else if .hasAutoPeersFallback }}
{{- $kmsCoreName := include "kmsCoreName" $ctx }}
{{- $peersIDList := untilStep (include "kmsPeersStartID" $ctx | int) ($ctx.Values.kmsPeers.count | add1 | int) 1 }}
{{- range $i := $peersIDList }}

[[threshold.peers]]
party_id = {{ int $i }}
mpc_identity = {{ .host | quote }}
address = {{ (printf "%s-%d" $kmsCoreName $i) | quote }}
port = {{ int $ctx.Values.kmsCore.ports.peer }}
{{- end }}
{{- end }}
{{- if $ctx.Values.redis.enabled }}
[threshold.preproc_redis]
host = {{ $ctx.Values.redis.host | quote }}
{{- end }}
{{- end }}

[telemetry]
tracing_service_name = {{ .serviceName | quote }}
{{- if $ctx.Values.tracing.enabled }}
tracing_endpoint = {{ $ctx.Values.tracing.endpoint | quote }}
{{- end }}

tracing_otlp_timeout_ms = 10000
metrics_bind_address = "0.0.0.0:{{ .metricsPort }}"
enable_sys_metrics = {{ $net.thresholdMode.enableSysMetrics }}
refresh_interval_ms = {{ $net.thresholdMode.refreshIntervalMs }}

[telemetry.batch]
max_queue_size = 8192
max_export_batch_size = 2048
max_concurrent_exports = 4
scheduled_delay_ms = 500
export_timeout_ms = 5000

[rate_limiter_conf]
bucket_size = {{ $ctx.Values.kmsCore.rateLimiter.bucketSize }}
pub_decrypt = 1
user_decrypt = 1
crsgen = 100
preproc = 50000
keygen = 1000
new_epoch = 25

[internal_config]
num_rayon_threads = {{ $net.thresholdMode.rayonNumThreads }}
num_tokio_threads = {{ $net.thresholdMode.tokioWorkerThreads }}
{{- end -}}

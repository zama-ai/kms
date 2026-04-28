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

{{/* takes the chart root context and renders the pod-local parent-side TUN bridge
      and DNS proxy used for enclave egress as a native Kubernetes sidecar.
      TCP ingress is DNATed into the enclave over the TUN. The tunnel values
      must match init_enclave.sh. */}}
{{- define "enclaveNetworkTunnelContainer" -}}
name: enclave-network-tunnel
image: {{ .Values.kmsCore.image.name }}:{{ .Values.kmsCore.image.tag }}
imagePullPolicy: {{ .Values.kmsCore.image.pullPolicy }}
env:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
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
    TUN_IF={{ .Values.kmsCore.nitroEnclave.networkTunnel.interfaceName | quote }}
    TUN_ADDR={{ .Values.kmsCore.nitroEnclave.networkTunnel.parentAddress | quote }}
    TUN_HOST="${TUN_ADDR%/*}"
    ENCLAVE_TUN_IP="10.118.0.2"
    TUN_SUBNET={{ .Values.kmsCore.nitroEnclave.networkTunnel.subnet | quote }}
    VSOCK_PORT={{ .Values.kmsCore.nitroEnclave.networkTunnel.vsockPort | quote }}
    UPSTREAM_DNS=""
    SOCAT_PID=""
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

    if [ -z "${POD_IP:-}" ]; then
      echo "enclave-network-tunnel: POD_IP is not set" >&2
      exit 1
    fi

    cleanup() {
      if [ -n "$SOCAT_PID" ]; then
        kill "$SOCAT_PID" 2>/dev/null || true
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
    socat -d0 \
      VSOCK-LISTEN:$VSOCK_PORT,fork,reuseaddr \
      TUN:$TUN_ADDR,tun-name=$TUN_IF,iff-up &
    SOCAT_PID=$!

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

    add_ingress_dnat() {
      port="$1"
      iptables -t nat -C PREROUTING -i eth0 -d "$POD_IP" -p tcp --dport "$port" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$port" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i eth0 -d "$POD_IP" -p tcp --dport "$port" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$port"
      iptables -C FORWARD -i eth0 -o "$TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$port" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i eth0 -o "$TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$port" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
    }

    add_ingress_dnat {{ .Values.kmsCore.ports.metrics | quote }}
    add_ingress_dnat {{ .Values.kmsCore.ports.client | quote }}
    {{- if .Values.kmsCore.thresholdMode.enabled }}
    add_ingress_dnat {{ .Values.kmsCore.ports.peer | quote }}
    {{- end }}

    dnsproxy -l "$TUN_HOST" -u "$UPSTREAM_DNS" &
    DNSPROXY_PID=$!

    while kill -0 "$SOCAT_PID" 2>/dev/null && kill -0 "$DNSPROXY_PID" 2>/dev/null; do
      sleep 1
    done

    if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
      SOCAT_STATUS=0
      wait "$SOCAT_PID" || SOCAT_STATUS=$?
      exit "$SOCAT_STATUS"
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

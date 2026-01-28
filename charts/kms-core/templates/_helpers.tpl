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
     	     	   "timeout" int
     	     	   "from" string
		      "to" string
		      "timeout" int (optional, defaults to 60)) */}}
{{- define "socatContainer" -}}
name: {{ .name }}
image: {{ .image.name }}:{{ .image.tag }}
imagePullPolicy: {{ .image.pullPolicy }}
restartPolicy: Always
command:
  - socat
args:
  - -d0
{{- if and (eq .name "grpc-peer-proxy") .timeout }}
  - -T{{ .timeout }}
{{- end }}
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

{{/* takes a (dict "name" string
                   "image" (dict "name" string "tag" string)
                   "vsockPort" int
		           "address" string
		           "port" int) */}}
{{- define "proxyFromEnclaveTcp" -}}
{{- include "proxyFromEnclave"
      (dict "name" .name
            "image" .image
            "vsockPort" .vsockPort
	      "to" (printf "TCP:%s:%d,nodelay" .address (int .port))) }}
{{- end -}}

{{/* takes a (dict "name" string
     	     	   "image" (dict "name" string "tag" string)
		           "from" string
		           "cid" int
                   "port" int
                   "timeout" int (optional, only used if name is "grpc-peer-proxy")) */}}
{{- define "proxyToEnclave" -}}
{{- include "socatContainer"
      (dict "name" .name
            "image" .image
            "from" .from
            "timeout" .timeout
	      "to" (printf "VSOCK-CONNECT:%d:%d" (int .cid) (int .port))) }}
{{- end -}}

{{/* takes a (dict "name" string
     	     	   "image" (dict "name" string "tag" string)
		           "cid" int
                   "port" int
                   "timeout" int (optional, only used if name is "grpc-peer-proxy")) */}}
{{- define "proxyToEnclaveTcp" -}}
{{- include "proxyToEnclave"
      (dict "name" .name
            "image" .image
            "from" (printf "TCP-LISTEN:%d,fork,nodelay,reuseaddr" (int .port))
            "cid" .cid
            "port" .port
            "timeout" .timeout) }}
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
if curl -s -f -o ./ca_pem_{{ .id }} "${S3_BASE_URL}/${CERT_PATH}"; then
  export KMS_CA_PEM_{{ .id }}="\"\"\"$(cat ./ca_pem_{{ .id }})\"\"\""
  echo "Successfully fetched CA cert for party {{ .id }}"
else
  echo "WARNING: No CA cert found for party {{ .id }} at ${CERT_PATH}"
fi
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
if curl -s -f -o ./key_pem "${S3_BASE_URL}/${KEY_PATH}"; then
  export KMS_KEY_PEM_{{ .Values.kmsPeers.id }}="\"\"\"$(cat ./key_pem)\"\"\""
  echo "Successfully fetched private key for party {{ .Values.kmsPeers.id }}"
else
  echo "WARNING: No private key found for party {{ .Values.kmsPeers.id }} at ${KEY_PATH}"
fi
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

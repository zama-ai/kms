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
{{- if $.Values.kmsCore.thresholdMode.tls.enabled }}
for i in $(seq 1 {{ len .Values.kmsCore.thresholdMode.peersList }}); do
BUCKET_PATH=$(curl -s "${CORE_CLIENT__S3_ENDPOINT}/?list-type=2&prefix=PUB-p${i}/CACert/" | grep -o "<Key>[^<]*</Key>" | sed "s/<Key>//;s/<\/Key>//")
curl -s -o ./ca_pem "${CORE_CLIENT__S3_ENDPOINT}/${BUCKET_PATH}"
export KMS_CA_PEM_${i}="\"\"\"$(cat ./ca_pem)\"\"\""
done
echo "### BEGIN - env ###"
env
echo "### END - env ###"
{{- end }}
{{- end -}}

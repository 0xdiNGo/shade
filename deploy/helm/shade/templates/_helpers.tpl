{{/*
Expand the name of the chart.
*/}}
{{- define "shade.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "shade.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "shade.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "shade.labels" -}}
helm.sh/chart: {{ include "shade.chart" . }}
{{ include "shade.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "shade.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shade.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference.
*/}}
{{- define "shade.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Mesh peers list for the rendered shade.toml.
Generates one "shade-N.shade.<namespace>.svc.cluster.local:7331" entry
per replica index (0 … replicaCount-1).
The daemon's setup_mesh self-filters the local node_id.
*/}}
{{- define "shade.meshPeers" -}}
{{- $ns := .Release.Namespace }}
{{- $fullname := include "shade.fullname" . }}
{{- $port := .Values.mesh.listenPort }}
{{- $count := .Values.replicaCount | int }}
{{- $peers := list }}
{{- range $i := until $count }}
{{- $peers = append $peers (printf "%s-%d.%s.%s.svc.cluster.local:%v" $fullname $i $fullname $ns $port) }}
{{- end }}
{{- toJson $peers }}
{{- end }}

{{/*
Name of the PKI Secret.
*/}}
{{- define "shade.pkiSecretName" -}}
{{- printf "%s-pki" (include "shade.fullname" .) }}
{{- end }}

{{/*
Name of the env-vars Secret (PSK + SASL password).
*/}}
{{- define "shade.secretsName" -}}
{{- printf "%s-secrets" (include "shade.fullname" .) }}
{{- end }}

{{/*
Common name helpers — standard Helm convention.
*/}}
{{- define "cepheus-admission.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cepheus-admission.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cepheus-admission.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "cepheus-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: admission-webhook
{{- end -}}

{{- define "cepheus-admission.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cepheus-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
TLS secret name — either the user-provided existing secret, or the
cert-manager-issued one (named after the release), or the self-signed
fallback.
*/}}
{{- define "cepheus-admission.tlsSecretName" -}}
{{- if .Values.tls.existingSecret -}}
{{- .Values.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "cepheus-admission.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
cert-manager Issuer name — uses the user-provided issuer if set,
otherwise the chart-managed self-signed issuer.
*/}}
{{- define "cepheus-admission.issuerName" -}}
{{- if .Values.tls.certManager.issuerName -}}
{{- .Values.tls.certManager.issuerName -}}
{{- else -}}
{{- printf "%s-selfsigned" (include "cepheus-admission.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate that EXACTLY ONE TLS mode is configured. The three modes
(cert-manager, existing secret, self-signed Job) are mutually exclusive
— enabling two would double-provision the TLS secret / caBundle. Fails
the render with an actionable message otherwise.
*/}}
{{- define "cepheus-admission.validateTls" -}}
{{- $modes := list -}}
{{- if .Values.tls.certManager.enabled -}}{{- $modes = append $modes "certManager.enabled" -}}{{- end -}}
{{- if .Values.tls.existingSecret -}}{{- $modes = append $modes "existingSecret" -}}{{- end -}}
{{- if .Values.tls.selfSigned -}}{{- $modes = append $modes "selfSigned" -}}{{- end -}}
{{- if ne (len $modes) 1 -}}
{{- fail (printf "tls: exactly one of certManager.enabled / existingSecret / selfSigned must be set (currently set: %v)" $modes) -}}
{{- end -}}
{{- end -}}

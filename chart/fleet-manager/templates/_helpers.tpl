{{- define "fleet-manager.name" -}}
fleet-manager
{{- end -}}

{{- define "fleet-manager.labels" -}}
app.kubernetes.io/name: {{ include "fleet-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "fleet-manager.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/*
Where a node's admin credentials Secret is mounted.
*/}}
{{- define "fleet-manager.nodeAdminDir" -}}
/etc/cryptos/fleet/node-admin/{{ . }}
{{- end -}}

{{/*
The nodes list for config.yaml. A node with adminCredsSecret gets its
adminCertPath, adminKeyPath and caCertPath pointed at that Secret's mount, and
the chart-only key is dropped. insecureSkipNodeVerify passes through and must
be a boolean.
*/}}
{{- define "fleet-manager.nodes" -}}
{{- $nodes := list }}
{{- range $i, $n := .Values.nodes }}
{{- if and (hasKey $n "insecureSkipNodeVerify") (not (kindIs "bool" $n.insecureSkipNodeVerify)) }}
{{- fail (printf "nodes[%d] (%s): insecureSkipNodeVerify must be true or false" $i ($n.name | default "")) }}
{{- end }}
{{- if $n.adminCredsSecret }}
{{- $name := required (printf "nodes[%d].name is required when adminCredsSecret is set" $i) $n.name }}
{{- range $k := list "adminCertPath" "adminKeyPath" "caCertPath" }}
{{- if hasKey $n $k }}
{{- fail (printf "nodes[%d] (%s): set adminCredsSecret or %s, not both; the chart points %s at the Secret" $i $name $k $k) }}
{{- end }}
{{- end }}
{{- $dir := include "fleet-manager.nodeAdminDir" $name }}
{{- $n = omit $n "adminCredsSecret" }}
{{- $_ := set $n "adminCertPath" (printf "%s/admin.crt" $dir) }}
{{- $_ = set $n "adminKeyPath" (printf "%s/admin.key" $dir) }}
{{- $_ = set $n "caCertPath" (printf "%s/ca.pem" $dir) }}
{{- end }}
{{- $nodes = append $nodes $n }}
{{- end }}
{{- toJson $nodes }}
{{- end -}}

{{/*
Where the operatorCRL.configMap files are mounted.
*/}}
{{- define "fleet-manager.operatorCRLDir" -}}
/etc/cryptos/fleet/operator-crl
{{- end -}}

{{/*
The operator revocation keys for config.yaml, checked the way the manager
checks them so a bad value fails the render instead of the start.
*/}}
{{- define "fleet-manager.operatorRevocation" -}}
{{- $crl := .Values.operatorCRL | default dict }}
{{- $urls := $crl.urls | default list }}
{{- $files := $crl.files | default list }}
{{- $ocsp := .Values.operatorOCSP | default dict }}
{{- $policy := .Values.operatorRevocationPolicy | default "" }}
{{- $set := or $urls $files $crl.configMap $policy $ocsp.mode $ocsp.url }}
{{- if and .Values.authBypass $set }}
{{- fail "operatorCRL, operatorRevocationPolicy and operatorOCSP need authBypass: false and an operator CA (operatorCA.configMap)" }}
{{- end }}
{{- if and $crl.configMap (not $files) }}
{{- fail "operatorCRL.configMap needs operatorCRL.files: the keys in the ConfigMap to load as CRLs" }}
{{- end }}
{{- if and $files (not $crl.configMap) }}
{{- fail "operatorCRL.files needs operatorCRL.configMap: the ConfigMap that holds them" }}
{{- end }}
{{- if not (has $policy (list "" "soft" "hard")) }}
{{- fail (printf "operatorRevocationPolicy must be soft or hard, not %q" $policy) }}
{{- end }}
{{- if not (has ($ocsp.mode | default "") (list "" "off" "aia" "url")) }}
{{- fail (printf "operatorOCSP.mode must be off, aia or url, not %q" $ocsp.mode) }}
{{- end }}
{{- if and (eq ($ocsp.mode | default "") "url") (not $ocsp.url) }}
{{- fail "operatorOCSP.url is required with operatorOCSP.mode url" }}
{{- end }}
{{- if and $ocsp.url (ne ($ocsp.mode | default "") "url") }}
{{- fail "operatorOCSP.url is only used with operatorOCSP.mode url" }}
{{- end }}
{{- range $i, $u := $urls }}
{{- if not (regexMatch "^https?://[^/]+" $u) }}
{{- fail (printf "operatorCRL.urls[%d] must be an http or https URL, not %q" $i $u) }}
{{- end }}
{{- end }}
{{- if or $urls $files }}
operatorCRL:
{{- range $urls }}
  - url: {{ . | quote }}
{{- end }}
{{- range $files }}
  - path: {{ printf "%s/%s" (include "fleet-manager.operatorCRLDir" $) . | quote }}
{{- end }}
{{- end }}
{{- if $policy }}
operatorRevocationPolicy: {{ $policy | quote }}
{{- end }}
{{- if $ocsp.mode }}
operatorOCSP:
  mode: {{ $ocsp.mode | quote }}
  {{- if $ocsp.url }}
  url: {{ $ocsp.url | quote }}
  {{- end }}
{{- end }}
{{- end -}}

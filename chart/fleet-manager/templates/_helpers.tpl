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

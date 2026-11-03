#!/usr/bin/env bash
# sync-chart.sh regenerates the Helm chart's copies of the CRD and manager Role
# from the controller-gen output under config/, re-applying the Helm templating
# wrappers that the kubebuilder helm plugin would produce.
#
# The chart ships its own copies of these manifests (chart/.../templates/crd and
# chart/.../templates/rbac). `make manifests` only regenerates config/, so without
# this sync the two drift apart. Run it after `make manifests`; the `manifests`
# target invokes it automatically.
#
# It intentionally rewrites ONLY the CRD and manager-role templates, leaving the
# chart's hand-customized values.yaml and manager.yaml untouched (unlike
# `kubebuilder edit --plugins=helm --force`, which would clobber them).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

crd_src_dir="config/crd/bases"
crd_dst_dir="chart/edgeguard-operator/templates/crd"
role_src="config/rbac/role.yaml"
role_dst="chart/edgeguard-operator/templates/rbac/manager-role.yaml"

sync_crd() {
  local src="$1"
  # controller-gen names files <group>_<plural>.yaml; the chart uses <plural>.<group>.yaml.
  local base group plural dst
  base="$(basename "$src" .yaml)"
  group="${base%_*}"
  plural="${base##*_}"
  dst="${crd_dst_dir}/${plural}.${group}.yaml"

  {
    echo '{{- if .Values.crd.enabled }}'
    # Drop the leading YAML document separator, and inject the resource-policy
    # conditional immediately after the metadata.annotations key.
    awk '
      NR == 1 && $0 == "---" { next }
      { print }
      !injected && $0 == "  annotations:" {
        print "    {{- if .Values.crd.keep }}"
        print "    \"helm.sh/resource-policy\": keep"
        print "    {{- end }}"
        injected = 1
      }
    ' "$src"
    echo '{{- end }}'
  } > "$dst"
  echo "Synced CRD -> $dst"
}

sync_role() {
  {
    cat <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
{{- if .Values.rbac.namespaced }}
kind: Role
{{- else }}
kind: ClusterRole
{{- end }}
metadata:
{{- if .Values.rbac.namespaced }}
  namespace: {{ .Release.Namespace }}
{{- end }}
  name: {{ include "edgeguard-operator.resourceName" (dict "suffix" "manager-role" "context" $) }}
EOF
    # Emit the rules verbatim, from the `rules:` key to the end of the generated Role.
    awk '/^rules:/ { r = 1 } r { print }' "$role_src"
  } > "$role_dst"
  echo "Synced Role -> $role_dst"
}

shopt -s nullglob
for crd in "$crd_src_dir"/*.yaml; do
  sync_crd "$crd"
done
sync_role

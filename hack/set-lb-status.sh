#!/usr/bin/env bash
#
# set-lb-status.sh - Fake the load balancer status on a Service for local testing.
#
# status.loadBalancer.ingress is a status subresource that a cloud/LB controller
# normally populates. On a cluster with no such controller (e.g. plain kind), it
# stays empty, so the operator never sees any IPs. This script patches the status
# subresource directly so you can exercise the port/IP discovery and upstream
# reporting paths without a real load balancer.
#
# Requires kubectl >= 1.24 (for --subresource=status).
#
# Usage:
#   hack/set-lb-status.sh [-n NAMESPACE] [-s SERVICE] [IP ...]
#
# Examples:
#   # Apply the sample Service, then assign one IPv4 and one IPv6:
#   kubectl apply -f hack/service.yaml
#   hack/set-lb-status.sh
#
#   # Custom service and addresses:
#   hack/set-lb-status.sh -n default -s my-service 203.0.113.10 2001:db8::10

set -euo pipefail

NAMESPACE="default"
SERVICE="my-service"

usage() {
	sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d'
	exit "${1:-0}"
}

while getopts ":n:s:h" opt; do
	case "${opt}" in
	n) NAMESPACE="${OPTARG}" ;;
	s) SERVICE="${OPTARG}" ;;
	h) usage 0 ;;
	*) usage 1 ;;
	esac
done
shift $((OPTIND - 1))

# Default to one IPv4 + one IPv6 from the documentation ranges (RFC 5737 / 3849).
IPS=("$@")
if [[ ${#IPS[@]} -eq 0 ]]; then
	IPS=("203.0.113.10" "2001:db8::10")
fi

# Build the ingress array JSON: [{"ip":"..."},{"ip":"..."}]
ingress=""
for ip in "${IPS[@]}"; do
	[[ -n "${ingress}" ]] && ingress+=","
	ingress+="{\"ip\":\"${ip}\"}"
done
patch="{\"status\":{\"loadBalancer\":{\"ingress\":[${ingress}]}}}"

echo "Patching ${NAMESPACE}/${SERVICE} load balancer status with: ${IPS[*]}"
kubectl patch service "${SERVICE}" -n "${NAMESPACE}" \
	--subresource=status --type=merge -p "${patch}"

echo "Current status.loadBalancer.ingress:"
kubectl get service "${SERVICE}" -n "${NAMESPACE}" \
	-o jsonpath='{.status.loadBalancer.ingress}{"\n"}'

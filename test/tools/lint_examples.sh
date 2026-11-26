#!/bin/bash
# Runs the example scenarios that write pcap files and lints the QUIC traffic of the captures.
#
# Usage (from anywhere, with the examples built):
#   contrib/quic/test/tools/lint_examples.sh [options of quic_pcap_lint.py]
# For example, --expect FILE fails only when a rule has more violations than FILE allows.

set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$root" || exit 1

for scenario in \
    "quic-example" \
    "erldp-transport-comparison --protocol=quic --numMessages=100 --interval=0.001 --lossRate=0.02" \
    "epmd-simulator-quic"; do
    if ! ./ns3 run --no-build --cwd "$work" "$scenario" >"$work/out.log" 2>&1; then
        echo "::error::failed: $scenario"
        tail -n 20 "$work/out.log"
        exit 1
    fi
done

exec python3 -I "$here/quic_pcap_lint.py" --mtu 1500 "$@" "$work"/*.pcap

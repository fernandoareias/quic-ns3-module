#!/bin/bash
# Behaviour oracle for refactors of the quic module that must not change what it sends.
#
# It runs a fixed set of short scenarios and prints one line "label digest" for each:
#   - quic-loss-stress with --digest: a hash of every packet (time and bytes) that left a device;
#   - erldp-mesh-exp1, erldp-mesh-exp2 and epmd-experimento: the SHA-256 of the CSV files.
# The digests of a build are compared with the ones recorded from an earlier build, so a change in
# the packets, in their timing or in their number shows up. The digests are recorded again each time
# the wire format changes on purpose; a refactor is checked against the digests of the build before it.
#
# Usage (the examples must have been built):
#   contrib/quic/test/oracle.sh record [file]   write the digests of this build
#   contrib/quic/test/oracle.sh check [file]    compare with the recorded ones (the default)
# The default file is contrib/quic/test/oracle.expected.

set -u

mode=${1:-check}
root=$(cd "$(dirname "$0")/../../.." && pwd)
expected=${2:-$root/contrib/quic/test/oracle.expected}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
result=$work/result.txt
: >"$result"
cd "$root" || exit 1

# run <label> <command>: runs one example and returns its combined output in $work/out.log
run() {
    if ! ./ns3 run --no-build --cwd "$work" "$2" >"$work/out.log" 2>&1; then
        echo "::error::scenario $1 failed: $2"
        tail -n 20 "$work/out.log"
        exit 1
    fi
}

digest_of_output() {
    grep -E '^(OK|FAIL|digest=)' "$work/out.log" | sha256sum | cut -c1-16
}

digest_of_files() {
    cat "$@" | sha256sum | cut -c1-16
}

for cc in ns3::QuicCubic ns3::QuicBbr ns3::QuicCongestionControl; do
    short=${cc#ns3::}
    for loss in 0 0.02 0.1; do
        for seed in 1 2; do
            run "stress" "quic-loss-stress --loss=$loss --run=$seed --nstreams=3 --bytes=200000 --cc=$cc --stop=120 --digest"
            echo "stress $short loss=$loss run=$seed $(digest_of_output)" >>"$result"
        done
    done
    run "stress-zrtt" "quic-loss-stress --loss=0.02 --run=1 --zrtt=1 --cc=$cc --stop=120 --digest"
    echo "stress $short zrtt loss=0.02 run=1 $(digest_of_output)" >>"$result"
    run "stress-vn" "quic-loss-stress --loss=0.05 --run=1 --vn=1 --cc=$cc --digest"
    echo "stress $short vn loss=0.05 run=1 $(digest_of_output)" >>"$result"
done

for experiment in erldp-mesh-exp1 erldp-mesh-exp2; do
    for protocol in quic quic-bbr quic-newreno; do
        out=$work/$experiment-$protocol
        run "$experiment" "$experiment --protocol=$protocol --nNodes=4 --run=1 --duration=5 --outputDir=$out"
        echo "$experiment $protocol $(digest_of_files "$out"/erldp-mesh-results.csv "$out"/erldp-mesh-events.csv)" >>"$result"
    done
done

for experiment in 1 2 3 4; do
    out=$work/epmd-$experiment
    mkdir -p "$out"
    run "epmd" "epmd-experimento --experiment=$experiment --protocol=quic --run=1 --outputDir=$out"
    echo "epmd-experimento $experiment quic $(digest_of_files "$out"/*.csv)" >>"$result"
done

case $mode in
record)
    cp "$result" "$expected"
    echo "recorded $(wc -l <"$expected") digests in $expected"
    ;;
check)
    if [ ! -f "$expected" ]; then
        echo "::error::no recorded digests in $expected"
        exit 1
    fi
    if diff -u "$expected" "$result"; then
        echo "oracle: $(wc -l <"$result") scenarios identical to the recorded ones"
    else
        echo "::error::the behaviour differs from the recorded one"
        exit 1
    fi
    ;;
*)
    echo "usage: $0 record|check [file]" >&2
    exit 2
    ;;
esac

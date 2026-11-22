#!/usr/bin/env python3
"""Low-latency media experiment: QUIC (this module) against TCP under uniform random packet loss.

One server sends three media flows (video, audio, metadata) over a single connection through a 10 Mbps, 20 ms
bottleneck that is otherwise idle; the client measures the one-way delivery delay of every message, counted from the
instant it was generated (examples/quic-video-streaming.cc). A message that never arrives counts as late. Loss is 0,
1, 2 and 3 %, every point is repeated 30 times with a different RngRun, and no transport uses TLS. Variants:

    tcp-ns3          TcpCubic with the ns-3 defaults (minimum RTO 1 s, SYN timeout 3 s, 200 ms delayed ACK, 128 KB buffers)
    tcp-linux        TcpCubic with the Linux values: 200 ms minimum RTO, 1 s SYN timeout, 40 ms delayed ACK, 4 MiB buffers
                     (the baseline of the tables)
    tcp-linux-pace   the same with TCP pacing on
    quic-rr          QuicCubic (paced), round-robin stream scheduling (the QUIC of the tables)
    quic-sfifo       QuicCubic, per-stream FIFO scheduling (the msquic default)

    ./ns3 build quic-video-streaming                      # from the ns-3 root, any build profile
    contrib/quic/scripts/streaming_experiment.py run      # runs the simulations, writes streaming-uniform-loss.csv
    contrib/quic/scripts/streaming_experiment.py tables   # LaTeX rows of the paper's Tables II and III

The simulations are deterministic: the same binary and the same seeds give the same CSV. Python 3 standard library only.
"""
import argparse
import concurrent.futures as cf
import csv
import math
import os
import pathlib
import statistics
import subprocess
import sys
from collections import defaultdict

HERE = pathlib.Path(os.path.abspath(__file__)).parent   # not resolved: contrib/quic may be a symbolic link
LOSSES = ['0', '0.01', '0.02', '0.03']
STREAMS = ['video', 'audio', 'meta']
VARIANTS = [('tcp-ns3', ['--transport=tcp', '--tcpProfile=ns3']),
            ('tcp-linux', ['--transport=tcp', '--tcpProfile=linux']),
            ('tcp-linux-pace', ['--transport=tcp', '--tcpProfile=linux', '--tcpPacing=1']),
            ('quic-rr', ['--transport=quic', '--sched=rr']),
            ('quic-sfifo', ['--transport=quic', '--sched=sfifo'])]
TCP, QUIC = 'tcp-linux', 'quic-rr'      # the pair of Tables II and III
HEADER = ['variant', 'transport', 'sched', 'cc', 'loss', 'run', 'stream', 'sent', 'delivered', 'mean_ms', 'p95_ms', 'p99_ms',
          'max_ms', 'goodput_mbps', 'corrupt', 'late150_pct', 'burst', 'jitter_ms', 'path_change', 'ttfb_ms', 'max_gap_ms',
          'undelivered']
# two-sided Student t, 95 %, 1..30 degrees of freedom
T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
       2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def find_binary(explicit):
    if explicit:
        return pathlib.Path(explicit)
    # the ns-3 root is three levels up from <root>/contrib/quic/scripts/, or the directory the script is run from
    roots = [HERE.parents[2], pathlib.Path.cwd()]
    for root in roots:
        d = root / 'build' / 'contrib' / 'quic' / 'examples'
        for suffix in ('-debug', '-optimized', '-default', ''):
            p = d / ('ns3-dev-quic-video-streaming' + suffix)
            if p.exists():
                return p
    sys.exit('quic-video-streaming binary not found under %s: run "./ns3 build quic-video-streaming" from the ns-3 root '
             'or pass --bin' % ' or '.join(str(r / 'build' / 'contrib' / 'quic' / 'examples') for r in roots))


def simulate(job):
    binary, variant, args, loss, run = job
    cmd = [str(binary), '--loss=' + loss, '--run=%d' % run, '--header=0'] + args
    p = subprocess.run(cmd, capture_output=True, text=True)
    rows = [l.split(',') for l in p.stdout.splitlines() if l.startswith(('quic,', 'tcp,'))]
    if p.returncode != 0 or len(rows) != 3:
        raise RuntimeError('simulation failed: %s\n%s' % (' '.join(cmd), p.stderr[-400:]))
    return [[variant] + r for r in rows]


def cmd_run(a):
    binary = find_binary(a.bin)
    jobs = [(binary, v, args, loss, r) for loss in LOSSES for v, args in VARIANTS for r in range(1, a.runs + 1)]
    rows = []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        for i, out in enumerate(ex.map(simulate, jobs), 1):
            rows += out
            if i % 20 == 0 or i == len(jobs):
                print('  %d/%d' % (i, len(jobs)), file=sys.stderr)
    with open(a.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)
    print('%s: %d rows' % (a.out, len(rows)))


def ic(v):
    """Mean and 95 % confidence half-width."""
    n = len(v)
    m = sum(v) / n
    return m, ((T95[n - 2] if n - 1 <= 30 else 1.96) * statistics.stdev(v) / math.sqrt(n) if n > 1 else 0.0)


def better(a, b):
    """a is smaller than b with separated intervals and a difference of at least 3 %."""
    return a[0] < b[0] and (b[0] - a[0]) > (a[1] + b[1]) and (b[0] - a[0]) >= 0.03 * b[0]


def num(x, nd):
    return ('%.*f' % (nd, x)).replace('.', '{,}')


def cell(mc, nd, bold=False):
    s = '%s$\\pm$%s' % (num(mc[0], nd), num(mc[1], nd))
    return '\\textbf{%s}' % s if bold else s


def cmd_tables(a):
    g = defaultdict(list)
    for r in csv.DictReader(open(a.csv)):
        g[(r['loss'], r['variant'], r['stream'])].append(r)
    reps = {len(v) for v in g.values()}
    assert len(reps) == 1, 'different number of repetitions: %s' % reps
    print('%% %d repetitions per point' % reps.pop())
    print('\n%% Table II: 95th percentile of the delivery delay (ms), TCP and QUIC per stream')
    for loss in LOSSES:
        cells = []
        for s in STREAMS:
            t = ic([float(r['p95_ms']) for r in g[(loss, TCP, s)]])
            q = ic([float(r['p95_ms']) for r in g[(loss, QUIC, s)]])
            cells += [cell(t, 0, better(t, q)), cell(q, 0, better(q, t))]
        print('%g\\%% & %s \\\\' % (float(loss) * 100, ' & '.join(cells)))
    print('\n%% Table III: audio delivered above 150 ms (%) and 99th percentile of the audio delay (ms)')
    for loss in LOSSES:
        late = {v: ic([float(r['late150_pct']) for r in g[(loss, v, 'audio')]]) for v in (TCP, QUIC)}
        p99 = {v: ic([float(r['p99_ms']) for r in g[(loss, v, 'audio')]]) for v in (TCP, QUIC)}
        print('%g\\%% & %s & %s & %s & %s \\\\' % (
            float(loss) * 100, cell(late[TCP], 2, better(late[TCP], late[QUIC])), cell(late[QUIC], 2, better(late[QUIC], late[TCP])),
            cell(p99[TCP], 0, better(p99[TCP], p99[QUIC])), cell(p99[QUIC], 0, better(p99[QUIC], p99[TCP]))))
    print('\n%% Table IV: sensitivity. 95th percentile of the audio delay (ms) at 1, 2 and 3 %% loss, audio late at 3 %%')
    names = [v for v, _ in VARIANTS]
    for v in names:
        cells = [cell(ic([float(r['p95_ms']) for r in g[(loss, v, 'audio')]]), 0) for loss in LOSSES[1:]]
        cells.append(cell(ic([float(r['late150_pct']) for r in g[('0.03', v, 'audio')]]), 2))
        print('%s & %s \\\\' % (v, ' & '.join(cells)))
    print('\n%% Messages that never arrived, runs with a connection that took over 1 s to open, per variant (all losses)')
    for v in names:
        und = sum(int(r['undelivered']) for loss in LOSSES for s in STREAMS for r in g[(loss, v, s)])
        slow = sum(1 for loss in LOSSES for r in g[(loss, v, 'video')] if float(r['ttfb_ms']) > 1000)
        print('%% %-15s undelivered %d, ttfb > 1 s in %d of %d runs' % (v, und, slow, 4 * len(g[('0', v, 'video')])))
    print('\n%% ratios of the mean 95th percentile, TCP (%s) over each QUIC variant (>1: QUIC is faster)' % TCP)
    for q in ('quic-rr', 'quic-sfifo'):
        for loss in LOSSES[1:]:
            rs = ['%s %.2f' % (st, statistics.mean(float(r['p95_ms']) for r in g[(loss, TCP, st)]) /
                               statistics.mean(float(r['p95_ms']) for r in g[(loss, q, st)])) for st in STREAMS]
            print('%% %-10s loss %-5s %s' % (q, loss, ', '.join(rs)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('run', help='run the simulations and write the CSV')
    p.add_argument('--bin', help='path of the quic-video-streaming binary (default: found under the ns-3 build directory)')
    p.add_argument('--runs', type=int, default=30, help='repetitions per point (default 30)')
    p.add_argument('--jobs', type=int, default=os.cpu_count() or 1, help='simulations in parallel')
    p.add_argument('--out', default='streaming-uniform-loss.csv')
    p.set_defaults(f=cmd_run)
    p = sp.add_parser('tables', help='print the LaTeX rows of Tables II and III from the CSV')
    p.add_argument('csv', nargs='?', default=str(HERE.parent / 'results' / 'streaming-uniform-loss.csv'))
    p.set_defaults(f=cmd_tables)
    a = ap.parse_args()
    a.f(a)


if __name__ == '__main__':
    main()

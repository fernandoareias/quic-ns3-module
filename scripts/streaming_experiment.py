#!/usr/bin/env python3
"""Streaming experiment: QUIC (this module) against TCP under uniform packet loss.

One server sends three media flows (video, audio, metadata) over a single connection through a 10 Mbps, 20 ms
bottleneck; the client measures the one-way delivery delay of every message (examples/quic-video-streaming.cc).
Loss is 0, 1, 2 and 3 %, every point is repeated 30 times with a different RngRun, TCP is TcpCubic without TLS and
QUIC is QuicCubic with round-robin stream scheduling.

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
VARIANTS = [('tcp', ['--transport=tcp', '--tls=0']),
            ('quic-rr', ['--transport=quic', '--sched=rr'])]
HEADER = ['variant', 'transport', 'sched', 'cc', 'loss', 'run', 'stream', 'sent', 'delivered', 'mean_ms', 'p95_ms', 'p99_ms',
          'max_ms', 'goodput_mbps', 'corrupt', 'late150_pct', 'burst', 'jitter_ms', 'path_change', 'ttfb_ms', 'max_gap_ms']
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
            t = ic([float(r['p95_ms']) for r in g[(loss, 'tcp', s)]])
            q = ic([float(r['p95_ms']) for r in g[(loss, 'quic-rr', s)]])
            cells += [cell(t, 0, better(t, q)), cell(q, 0, better(q, t))]
        print('%g\\%% & %s \\\\' % (float(loss) * 100, ' & '.join(cells)))
    print('\n%% Table III: goodput (the three streams summed, Mbps) and audio delivered above 150 ms (%)')
    for loss in LOSSES:
        goodput, late = {}, {}
        for v in ('tcp', 'quic-rr'):
            per_run = defaultdict(float)
            for s in STREAMS:
                for r in g[(loss, v, s)]:
                    per_run[r['run']] += float(r['goodput_mbps'])
            goodput[v] = ic(list(per_run.values()))
            late[v] = ic([float(r['late150_pct']) for r in g[(loss, v, 'audio')]])
        print('%g\\%% & %s & %s & %s & %s \\\\' % (
            float(loss) * 100, cell(goodput['tcp'], 3), cell(goodput['quic-rr'], 3),
            cell(late['tcp'], 2, better(late['tcp'], late['quic-rr'])),
            cell(late['quic-rr'], 2, better(late['quic-rr'], late['tcp']))))


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

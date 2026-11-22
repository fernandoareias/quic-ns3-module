#!/usr/bin/env python3
"""Low-latency media experiment: QUIC (this module) against TCP under random packet loss.

One server sends three media flows (video, audio, metadata) over a single connection through a 10 Mbps, 20 ms
bottleneck that is otherwise idle (about 11 % load, no cross traffic); the client measures the one-way delivery delay
of every message, counted from the instant it was generated (examples/quic-video-streaming.cc). A message that never
arrives counts as late. Loss is applied in the server-to-client direction: uniform at 0, 1, 2 and 3 %, and in bursts
(mean length 4) at 1, 2 and 3 %. Every point is repeated 30 times with a different RngRun and no transport uses TLS.
Variants:

    tcp-ns3         TcpCubic with the ns-3 defaults (minimum RTO 1 s, SYN timeout 3 s, 200 ms delayed ACK, 128 KB buffers)
    tcp-linux       TcpCubic with the Linux timers and buffers: 200 ms minimum RTO, 1 s SYN timeout, 40 ms delayed ACK,
                    4 MiB buffers (the baseline of the tables; it is still the ns-3 TCP: no Tail Loss Probe, no RACK)
    tcp-linux-pace  the same with TCP pacing on
    quic-rr         QuicCubic (paced), round-robin stream scheduling (the QUIC of Tables II and III)
    quic-sfifo      QuicCubic, per-stream FIFO scheduling (the msquic default)

    ./ns3 build quic-video-streaming                      # from the ns-3 root, any build profile
    contrib/quic/scripts/streaming_experiment.py run      # runs the simulations, writes streaming-loss.csv
    contrib/quic/scripts/streaming_experiment.py tables   # LaTeX rows of the paper's tables

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
POINTS = [('u', '0'), ('u', '0.01'), ('u', '0.02'), ('u', '0.03'), ('b', '0.01'), ('b', '0.02'), ('b', '0.03')]
LOSSES = ['0', '0.01', '0.02', '0.03']
STREAMS = ['video', 'audio', 'meta']
VARIANTS = [('tcp-ns3', ['--transport=tcp', '--tcpProfile=ns3']),
            ('tcp-linux', ['--transport=tcp', '--tcpProfile=linux-timers']),
            ('tcp-linux-pace', ['--transport=tcp', '--tcpProfile=linux-timers', '--tcpPacing=1']),
            ('quic-rr', ['--transport=quic', '--sched=rr']),
            ('quic-sfifo', ['--transport=quic', '--sched=sfifo'])]
TCP, QUIC = 'tcp-linux', 'quic-rr'      # the pair of Tables II and III
HEADER = ['variant', 'transport', 'sched', 'cc', 'loss', 'run', 'stream', 'sent', 'delivered', 'mean_ms', 'p95_ms', 'p99_ms',
          'max_ms', 'goodput_mbps', 'corrupt', 'late150_pct', 'burst', 'jitter_ms', 'path_change', 'ttfb_ms', 'max_gap_ms',
          'undelivered', 'rto_episodes', 'pacing_below_pct']
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
    binary, variant, args, scenario, loss, run = job
    cmd = [str(binary), '--loss=' + loss, '--run=%d' % run, '--header=0'] + (['--burst=4'] if scenario == 'b' else []) + args
    p = subprocess.run(cmd, capture_output=True, text=True)
    rows = [l.split(',') for l in p.stdout.splitlines() if l.startswith(('quic,', 'tcp,'))]
    if p.returncode != 0 or len(rows) != 3:
        raise RuntimeError('simulation failed: %s\n%s' % (' '.join(cmd), p.stderr[-400:]))
    return [[variant] + r for r in rows]


def cmd_run(a):
    binary = find_binary(a.bin)
    jobs = [(binary, v, args, sc, loss, r) for sc, loss in POINTS for v, args in VARIANTS for r in range(1, a.runs + 1)]
    rows = []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        for i, out in enumerate(ex.map(simulate, jobs), 1):
            rows += out
            if i % 50 == 0 or i == len(jobs):
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
        g[('b' if float(r['burst']) > 0 else 'u', r['loss'], r['variant'], r['stream'])].append(r)
    reps = {len(v) for v in g.values()}
    assert len(reps) == 1, 'different number of repetitions: %s' % reps
    print('%% %d repetitions per point' % reps.pop())

    def metric(sc, loss, v, st, col):
        return ic([float(r[col]) for r in g[(sc, loss, v, st)]])

    print('\n%% Table II: 95th percentile of the delivery delay (ms), TCP and QUIC per stream, uniform loss')
    for loss in LOSSES:
        cells = []
        for s in STREAMS:
            t, q = metric('u', loss, TCP, s, 'p95_ms'), metric('u', loss, QUIC, s, 'p95_ms')
            cells += [cell(t, 0, better(t, q)), cell(q, 0, better(q, t))]
        print('%g\\%% & %s \\\\' % (float(loss) * 100, ' & '.join(cells)))

    print('\n%% Table III: audio delivered above 150 ms (%) and 99th percentile of the audio delay (ms), uniform loss')
    for loss in LOSSES:
        late = {v: metric('u', loss, v, 'audio', 'late150_pct') for v in (TCP, QUIC)}
        p99 = {v: metric('u', loss, v, 'audio', 'p99_ms') for v in (TCP, QUIC)}
        print('%g\\%% & %s & %s & %s & %s \\\\' % (
            float(loss) * 100, cell(late[TCP], 2, better(late[TCP], late[QUIC])), cell(late[QUIC], 2, better(late[QUIC], late[TCP])),
            cell(p99[TCP], 0, better(p99[TCP], p99[QUIC])), cell(p99[QUIC], 0, better(p99[QUIC], p99[TCP]))))

    def sensitivity(title, sc, names):
        print('\n%% %s: audio p95 (ms) at 1, 2 and 3 %% loss, audio p99 (ms) and audio late (%%) at 3 %%' % title)
        for v in names:
            cells = [cell(metric(sc, loss, v, 'audio', 'p95_ms'), 0) for loss in LOSSES[1:]]
            cells.append(cell(metric(sc, '0.03', v, 'audio', 'p99_ms'), 0))
            cells.append(cell(metric(sc, '0.03', v, 'audio', 'late150_pct'), 2))
            print('%s & %s \\\\' % (v, ' & '.join(cells)))

    sensitivity('Table IV (uniform loss)', 'u', [v for v, _ in VARIANTS])
    sensitivity('Table V (burst loss, mean length 4 packets)', 'b', [TCP, QUIC, 'quic-sfifo'])

    print('\n%% TCP RTO episodes (consecutive timeouts count once) per run, and the audio p95 of the runs without any against the runs with at least one')
    for v in ('tcp-ns3', TCP, 'tcp-linux-pace'):
        for sc, loss in POINTS[1:]:
            runs = g[(sc, loss, v, 'audio')]
            rto = [int(r['rto_episodes']) for r in runs]
            free = [float(r['p95_ms']) for r in runs if int(r['rto_episodes']) == 0]
            hit = [float(r['p95_ms']) for r in runs if int(r['rto_episodes']) > 0]
            print('%% %-15s %s %-5s RTO episodes/run %.2f, runs with one %2d: p95 %s | without: p95 %s' % (
                v, sc, loss, statistics.mean(rto), len(hit),
                '%.0f' % statistics.mean(hit) if hit else '-', '%.0f' % statistics.mean(free) if free else '-'))

    print('\n%% TCP with pacing: share of the media window (%%) in which the pacing rate was below the offered load')
    for sc, loss in POINTS[1:]:
        v = [float(r['pacing_below_pct']) for r in g[(sc, loss, 'tcp-linux-pace', 'audio')]]
        print('%% %s %-5s mean %.1f %%, min %.1f %%, max %.1f %%' % (sc, loss, statistics.mean(v), min(v), max(v)))

    print('\n%% Messages that never arrived and runs with a connection that took over 1 s to open, per variant')
    for v, _ in VARIANTS:
        und = sum(int(r['undelivered']) for sc, loss in POINTS for s in STREAMS for r in g[(sc, loss, v, s)])
        slow = sum(1 for sc, loss in POINTS for r in g[(sc, loss, v, 'video')] if float(r['ttfb_ms']) > 1000)
        total = sum(len(g[(sc, loss, v, 'video')]) for sc, loss in POINTS)
        print('%% %-15s undelivered %d, ttfb > 1 s in %d of %d runs' % (v, und, slow, total))

    print('\n%% ratios of the mean 95th percentile, TCP (%s) over each QUIC variant (>1: QUIC is faster)' % TCP)
    for sc in ('u', 'b'):
        for q in ('quic-rr', 'quic-sfifo'):
            for loss in LOSSES[1:]:
                rs = ['%s %.2f' % (st, statistics.mean(float(r['p95_ms']) for r in g[(sc, loss, TCP, st)]) /
                                   statistics.mean(float(r['p95_ms']) for r in g[(sc, loss, q, st)])) for st in STREAMS]
                print('%% %s %-10s loss %-5s %s' % (sc, q, loss, ', '.join(rs)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('run', help='run the simulations and write the CSV')
    p.add_argument('--bin', help='path of the quic-video-streaming binary (default: found under the ns-3 build directory)')
    p.add_argument('--runs', type=int, default=30, help='repetitions per point (default 30)')
    p.add_argument('--jobs', type=int, default=os.cpu_count() or 1, help='simulations in parallel')
    p.add_argument('--out', default='streaming-loss.csv')
    p.set_defaults(f=cmd_run)
    p = sp.add_parser('tables', help='print the LaTeX rows of the tables from the CSV')
    p.add_argument('csv', nargs='?', default=str(HERE.parent / 'results' / 'streaming-loss.csv'))
    p.set_defaults(f=cmd_tables)
    a = ap.parse_args()
    a.f(a)


if __name__ == '__main__':
    main()

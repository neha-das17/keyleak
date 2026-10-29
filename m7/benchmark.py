#!/usr/bin/env python3
"""M7 end-to-end process benchmark. Run from anywhere in the KeyLeak repo."""
import argparse
import csv
import json
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / 'results'
TARGETS = {'vulnerable': ROOT / 'vulnerable' / 'server',
           'patched': ROOT / 'patched' / 'server_patched'}


def run(binary, timeout):
    start = time.perf_counter_ns()
    proc = subprocess.run([str(binary)], input=b'HELLO\n', stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    if proc.returncode != 0:
        raise RuntimeError(f'{binary} exited {proc.returncode}: {proc.stderr.decode(errors="replace")}')
    expected = b'[M1] AES-256-GCM test: PASS' if binary == TARGETS['vulnerable'] else b'[M5] AES-GCM self-test: PASS'
    if expected not in proc.stdout:
        raise RuntimeError(f'Cryptographic self-test missing for {binary}')
    return elapsed


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runs', type=int, default=100)
    p.add_argument('--warmup', type=int, default=5)
    p.add_argument('--timeout', type=float, default=5)
    args = p.parse_args()
    if args.runs < 2 or args.warmup < 0:
        p.error('Use at least 2 runs and nonnegative warmup')
    for name, path in TARGETS.items():
        if not path.is_file():
            p.error(f'Missing {name} executable: {path}')
    OUT.mkdir(parents=True, exist_ok=True)
    for name, binary in TARGETS.items():
        for _ in range(args.warmup):
            run(binary, args.timeout)
    rows = []
    samples = {name: [] for name in TARGETS}
    # Alternate order to reduce systematic bias from machine drift.
    for i in range(args.runs):
        names = list(TARGETS) if i % 2 == 0 else list(reversed(TARGETS))
        for name in names:
            ms = run(TARGETS[name], args.timeout)
            samples[name].append(ms)
            rows.append({'iteration': i + 1, 'target': name, 'elapsed_ms': f'{ms:.6f}'})
    with (OUT / 'timings.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['iteration', 'target', 'elapsed_ms'])
        writer.writeheader()
        writer.writerows(rows)
    summary = {}
    for name, values in samples.items():
        summary[name] = {'runs': len(values), 'mean_ms': statistics.mean(values),
                         'median_ms': statistics.median(values),
                         'stddev_ms': statistics.stdev(values),
                         'min_ms': min(values), 'max_ms': max(values)}
    v = summary['vulnerable']['median_ms']
    q = summary['patched']['median_ms']
    summary['median_overhead_percent'] = 100 * (q - v) / v
    (OUT / 'benchmark_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('M7 process-level benchmark (includes startup, OpenSSL, I/O)')
    for name, item in summary.items():
        if isinstance(item, dict):
            print(f"{name:11} mean={item['mean_ms']:.4f} ms median={item['median_ms']:.4f} ms stddev={item['stddev_ms']:.4f} ms")
    print(f"Median overhead: {summary['median_overhead_percent']:+.2f}%")
    print(f'Results: {OUT}')
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4))
        labels = ['Vulnerable', 'Patched']
        medians = [summary['vulnerable']['median_ms'], summary['patched']['median_ms']]
        bars = ax.bar(labels, medians)
        ax.set_ylabel('Median elapsed time (ms)')
        ax.set_title('KeyLeak: End-to-end process time')
        for bar, value in zip(bars, medians):
            ax.text(bar.get_x() + bar.get_width()/2, value, f'{value:.3f}', ha='center', va='bottom')
        ax.set_ylim(0, max(medians) * 1.2)
        fig.tight_layout()
        fig.savefig(OUT / 'execution_time.png', dpi=180)
        plt.close(fig)
        print('Graph: execution_time.png')
    except ImportError:
        print('Graph skipped: install matplotlib with python3 -m pip install matplotlib')


if __name__ == '__main__':
    main()

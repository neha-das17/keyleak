#!/usr/bin/env python3
"""Summarize observed M6 outcomes; do not infer canary or full memory erasure."""
import csv
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
M6 = ROOT / 'm6' / 'results.csv'
OUT = Path(__file__).resolve().parent / 'results'

def is_true(s):
    return str(s).strip().lower() in ('true', 'yes', '1')

def main():
    if not M6.exists():
        raise SystemExit(f'Missing M6 data: {M6}; run python3 m6/verify.py first')
    with M6.open(newline='') as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit('M6 CSV is empty')
    required = ['Test ID', 'Payload Length', 'Vulnerable Key Matches',
                'Patched Key Disclosure', 'Patched AES', 'Result']
    for col in required:
        if col not in rows[0]:
            raise SystemExit(f'M6 CSV missing column: {col}')
    OUT.mkdir(parents=True, exist_ok=True)
    total = len(rows)
    success = sum(r['Result'].strip().upper() == 'PASS' for r in rows)
    vulnerable_recovery = sum(is_true(r['Vulnerable Key Matches']) for r in rows)
    patched_disclosure = sum(is_true(r['Patched Key Disclosure']) for r in rows)
    patched_aes = sum(is_true(r['Patched AES']) for r in rows)
    summary = {'tests': total, 'passed': success,
               'pass_rate_percent': 100 * success / total,
               'vulnerable_key_match_tests': vulnerable_recovery,
               'patched_known_disclosure_label_tests': patched_disclosure,
               'patched_aes_pass_tests': patched_aes}
    (OUT / 'security_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('KeyLeak M7: M6 results summary')
    for k, v in summary.items():
        print(f'  {k}: {v}')
    print('\nTest details:')
    for r in rows:
        print(f"  {r['Test ID']}: {r['Payload Length']} bytes, {r['Result']}")
    print('\nScope: patched disclosure check searches known output labels; not a proof of absence of all leaks.')
    print('Canary triggering and full-process zeroization are not established by these tests.')
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4))
        values = [vulnerable_recovery, patched_disclosure]
        bars = ax.bar(['Vulnerable: key matches', 'Patched: known leak labels'], values)
        ax.set_ylabel('Number of tests')
        ax.set_ylim(0, total + 0.7)
        ax.set_title('KeyLeak M6: observed disclosure indicators')
        for bar, val in zip(bars, values):
            ax.text(bar.get_x()+bar.get_width()/2, val + 0.06, str(val), ha='center')
        fig.tight_layout()
        fig.savefig(OUT / 'security_comparison.png', dpi=180)
        plt.close(fig)
        print('Graph: security_comparison.png')
    except ImportError:
        print('Graph skipped: install matplotlib')

if __name__ == '__main__':
    main()

"""Append clearly synthetic traffic for exercising the live monitor."""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('data/monitor-demo.jsonl'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    print(f'Writing 30 synthetic requests to {args.output}; no real traffic is generated.', flush=True)
    for i in range(30):
        event = {'timestamp': datetime.now(timezone.utc).isoformat(), 'source': 'app',
                 'path': '/checkout', 'status': 200 if i < 20 else 503,
                 'message': 'Synthetic demo: checkout OK' if i < 20 else 'Synthetic demo: payment provider timeout'}
        with args.output.open('a', encoding='utf-8') as file:
            file.write(json.dumps(event) + '\n')
        time.sleep(.5)
    print('Demo finished. The monitor continues; the incident resolves after the quiet period.', flush=True)


if __name__ == '__main__':
    main()

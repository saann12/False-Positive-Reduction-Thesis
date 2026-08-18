"""
capture.py
Reads Suricata eve.json continuously
and picks up new alerts in real time.
"""

import json
import time
import os

EVE_JSON_PATH = '/var/log/suricata/eve.json'
OUTPUT_PATH   = os.path.join(os.path.dirname(__file__), 'raw_alerts.json')


def read_alerts():
    """Read all alerts from eve.json."""
    alerts = []
    try:
        with open(EVE_JSON_PATH, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        alerts.append(event)
                except:
                    pass
    except FileNotFoundError:
        print(f'[!] eve.json not found at {EVE_JSON_PATH}')
        print('[!] Make sure Suricata is running')
    return alerts


def save_raw_alerts(alerts):
    """Save raw alerts for feature mapping."""
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(alerts, f, indent=2)


def run():
    print('[*] Starting capture — reading Suricata eve.json')
    print('[*] Press Ctrl+C to stop\n')

    seen = 0
    while True:
        try:
            alerts = read_alerts()
            new = len(alerts) - seen

            if new > 0:
                print(f'[+] {new} new alert(s) detected — total: {len(alerts)}')
                save_raw_alerts(alerts)
                seen = len(alerts)
            else:
                print(f'[.] Watching for alerts... (total so far: {seen})')

            time.sleep(5)

        except KeyboardInterrupt:
            print('\n[*] Capture stopped')
            break


if __name__ == '__main__':
    run()
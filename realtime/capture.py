"""
capture.py
Reads Suricata eve.json continuously
and picks up new alerts in real time.
Includes alert deduplication and position tracking.
"""
import json
import time
import os
from collections import defaultdict

EVE_JSON_PATH = '/var/log/suricata/eve.json'
OUTPUT_PATH   = os.path.join(os.path.dirname(__file__), 'raw_alerts.json')

def read_new_alerts(last_position=0):
    """Read only new alerts since last check using file position."""
    alerts = []
    try:
        with open(EVE_JSON_PATH, 'r') as f:
            f.seek(last_position)
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        alerts.append(event)
                except:
                    pass
            new_position = f.tell()
        return alerts, new_position
    except FileNotFoundError:
        print(f'[!] eve.json not found at {EVE_JSON_PATH}')
        print('[!] Make sure Suricata is running')
        return [], last_position
    except Exception as e:
        print(f'[!] Error reading eve.json: {e}')
        return [], last_position

def read_all_alerts():
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
    return alerts

def deduplicate_alerts(alerts):
    """
    Group duplicate alerts by signature.
    Shows count instead of repeating same alert.
    Keeps most recent timestamp.
    """
    seen = {}
    for alert in alerts:
        sig = alert.get('alert', {}).get('signature', 'Unknown')
        src = alert.get('src_ip', '')
        key = f"{sig}_{src}"

        if key in seen:
            seen[key]['count'] += 1
            seen[key]['last_seen'] = alert.get('timestamp', '')
        else:
            seen[key] = {
                'raw':        alert,
                'count':      1,
                'first_seen': alert.get('timestamp', ''),
                'last_seen':  alert.get('timestamp', '')
            }

    # Return deduplicated list with count info
    result = []
    for key, data in seen.items():
        alert = data['raw'].copy()
        alert['count']      = data['count']
        alert['first_seen'] = data['first_seen']
        alert['last_seen']  = data['last_seen']
        result.append(alert)

    return result

def save_raw_alerts(alerts):
    """Save raw alerts for feature mapping."""
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(alerts, f, indent=2)

def get_file_size():
    """Get current eve.json file size for position tracking."""
    try:
        return os.path.getsize(EVE_JSON_PATH)
    except:
        return 0

def run():
    print('[*] Starting capture — reading Suricata eve.json')
    print('[*] Press Ctrl+C to stop\n')

    # Read all existing alerts on startup
    all_alerts = read_all_alerts()
    save_raw_alerts(all_alerts)
    last_position = get_file_size()
    total = len(all_alerts)

    print(f'[*] Loaded {total} existing alerts from eve.json')

    while True:
        try:
            # Only read new lines since last check
            new_alerts, last_position = read_new_alerts(last_position)

            if new_alerts:
                all_alerts.extend(new_alerts)
                deduped = deduplicate_alerts(all_alerts)
                save_raw_alerts(all_alerts)  # save all for feature mapping
                total = len(all_alerts)
                unique = len(deduped)
                print(f'[+] {len(new_alerts)} new alert(s) — total: {total} | unique signatures: {unique}')
            else:
                print(f'[.] Watching for alerts... (total: {total})', end='\r')

            time.sleep(5)

        except KeyboardInterrupt:
            print('\n[*] Capture stopped')
            break
        except Exception as e:
            print(f'\n[!] Error: {e}')
            time.sleep(5)
            continue

if __name__ == '__main__':
    run()
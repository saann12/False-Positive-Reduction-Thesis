"""
run.py
Runs the complete IDS false positive reduction pipeline
with a single command.

Usage: sudo python3 run.py
"""


import subprocess
import threading
import time
import os
import sys

# Paths
REALTIME_DIR  = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(REALTIME_DIR, 'dashboard')


def run_capture():
    """Run capture.py continuously."""
    print('[*] Starting capture module...')
    try:
        subprocess.run(
            ['python3', os.path.join(REALTIME_DIR, 'capture.py')]
        )
    except Exception as e:
        print(f'[!] Capture error: {e}')


def run_predict():
    """Run predict.py every 15 seconds."""
    print('[*] Starting prediction module...')
    time.sleep(5)  # wait for capture to get first alerts
    while True:
        try:
            subprocess.run(
                ['python3', os.path.join(REALTIME_DIR, 'predict.py')]
            )
        except Exception as e:
            print(f'[!] Predict error: {e}')
        time.sleep(15)


def run_dashboard():
    """Run Flask dashboard."""
    print('[*] Starting dashboard...')
    print('[*] Open http://localhost:5000 in your browser\n')
    try:
        subprocess.run(
            ['python3', os.path.join(DASHBOARD_DIR, 'app.py')]
        )
    except Exception as e:
        print(f'[!] Dashboard error: {e}')


def main():
    print('=' * 55)
    print('  IDS False Positive Reduction System')
    print('  Nepali Commercial Banks — SOC Dashboard')
    print('  Stacked RF+XGBoost Post-Alert Module')
    print('=' * 55)
    print()
    print('[*] Starting all modules...')
    print('[*] Press Ctrl+C to stop everything\n')

    # Start all three modules in separate threads
    threads = [
        threading.Thread(target=run_capture,   daemon=True),
        threading.Thread(target=run_predict,   daemon=True),
        threading.Thread(target=run_dashboard, daemon=False),
    ]

    for t in threads:
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print('\n[*] Stopping all modules...')
        print('[*] System stopped')
        sys.exit(0)


if __name__ == '__main__':
    main()
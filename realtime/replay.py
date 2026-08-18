"""
replay.py
─────────────────────────────────────────────
Streams unlimited CICIDS2017 flows through
the stacked RF+XGBoost pipeline continuously,
simulating live network traffic for the
SOC dashboard.

Usage:
    python3 replay.py

Press Ctrl+C to stop and see final results.
"""

import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import joblib
import json
import os
import time
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_PATH   = os.path.join(BASE_DIR, '../data/raw/')
MODELS_PATH = os.path.join(BASE_DIR, '../models/')
ALERTS_JSON = os.path.join(BASE_DIR, 'alerts.json')
FEATURES    = os.path.join(BASE_DIR, '../data/processed/feature_names.csv')

# ── Attack type labels ─────────────────────────────────────────────────
ATTACK_TYPES = {
    'BENIGN':           'Normal Traffic',
    'DDoS':             'DDoS Attack',
    'DoS Hulk':         'DoS Hulk Attack',
    'DoS GoldenEye':    'DoS GoldenEye Attack',
    'DoS slowloris':    'DoS Slowloris Attack',
    'DoS Slowhttptest': 'DoS SlowHTTP Attack',
    'Heartbleed':       'Heartbleed Exploit',
    'PortScan':         'Port Scan',
    'Bot':              'Botnet Activity',
    'Infiltration':     'Network Infiltration',
    'Web Attack':       'Web Attack',
    'FTP-Patator':      'Brute Force FTP',
    'SSH-Patator':      'Brute Force SSH',
}

# ── Simulated IPs for Nepal banking context ────────────────────────────
INTERNAL_IPS = [f'192.168.{i}.{j}' for i in range(1, 5) for j in range(1, 50)]
EXTERNAL_IPS = [f'203.{i}.{j}.{k}' for i in range(1, 10)
                for j in range(1, 10) for k in range(1, 10)]
SERVER_IPS   = [f'10.0.0.{i}' for i in range(1, 20)]


def load_models():
    """Load trained stacked RF+XGBoost models."""
    rf_model  = joblib.load(os.path.join(MODELS_PATH, 'random_forest_model.pkl'))
    xgb_model = joblib.load(os.path.join(MODELS_PATH, 'xgboost_stacked_model.pkl'))
    scaler    = joblib.load(os.path.join(MODELS_PATH, 'scaler.pkl'))
    print('[*] Models loaded successfully')
    return rf_model, xgb_model, scaler


def load_dataset():
    """Load CICIDS2017 CSV files."""
    feature_names = pd.read_csv(FEATURES).iloc[:, 0].tolist()

    files = [
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        'Wednesday-workingHours.pcap_ISCX.csv',
    ]

    dfs = []
    for f in files:
        path = os.path.join(DATA_PATH, f)
        if os.path.exists(path):
            temp = pd.read_csv(path, low_memory=False)
            temp.columns = temp.columns.str.strip()
            dfs.append(temp)
            print(f'[*] Loaded {f} — {len(temp):,} rows')
        else:
            print(f'[!] File not found: {f}')

    df = pd.concat(dfs, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    available = [f for f in feature_names if f in df.columns]
    print(f'[*] Total: {len(df):,} flows | Features: {len(available)}')
    print(f'[*] Attack types: {list(df["Label"].unique())}')
    return df, available


def get_random_batch(df, available, batch_size=50):
    normal_size  = int(batch_size * 0.8)
    attack_size  = int(batch_size * 0.2)
    normal  = df[df['Label'] == 'BENIGN'].sample(
        min(normal_size, len(df[df['Label'] == 'BENIGN'])),
        random_state=np.random.randint(0, 99999)
    )
    attacks = df[df['Label'] != 'BENIGN'].sample(
        min(attack_size, len(df[df['Label'] != 'BENIGN'])),
        random_state=np.random.randint(0, 99999)
    )
    batch = pd.concat([normal, attacks]).sample(frac=1)
    return batch[available], batch['Label']


def classify_flow(row, label, rf_model, xgb_model, scaler, flow_id):
    """
    Classify a single network flow using stacked model.

    Stage 1: Random Forest → probability score
    Stage 2: XGBoost takes RF score + original features → final decision

    Returns classification result with ground truth for FPR calculation.
    """
    features        = row.values.reshape(1, -1)
    features_scaled = scaler.transform(features)

    # Stage 1 — Random Forest
    rf_prob = rf_model.predict_proba(features_scaled)[:, 1]

    # Stage 2 — Stacked XGBoost
    stacked      = np.column_stack([features_scaled, rf_prob])
    prediction   = xgb_model.predict(stacked)[0]
    confidence   = round(float(xgb_model.predict_proba(stacked)[0][1]) * 100, 1)

    # Ground truth and correctness
    actual_attack    = label != 'BENIGN'
    predicted_attack = bool(prediction == 1)
    correct          = actual_attack == predicted_attack
    attack_type      = ATTACK_TYPES.get(label, label)

    # Determine classification type
    if actual_attack and predicted_attack:
        classification = 'True Positive'       # real attack correctly detected
    elif not actual_attack and not predicted_attack:
        classification = 'True Negative'       # normal correctly suppressed
    elif not actual_attack and predicted_attack:
        classification = 'False Positive'      # normal wrongly flagged as attack
    else:
        classification = 'False Negative'      # real attack missed

    # Simulate realistic Nepal banking IPs
    if actual_attack:
        src_ip  = np.random.choice(EXTERNAL_IPS)
        dest_ip = np.random.choice(SERVER_IPS)
    else:
        src_ip  = np.random.choice(INTERNAL_IPS)
        dest_ip = np.random.choice(SERVER_IPS)

    return {
        'id':             flow_id,
        'timestamp':      datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        'src_ip':         src_ip,
        'dest_ip':        dest_ip,
        'proto':          np.random.choice(['TCP', 'UDP', 'TCP', 'TCP']),
        'signature':      attack_type,
        'is_attack':      predicted_attack,
        'confidence':     confidence,
        'actual_label':   label,
        'correct':        correct,
        'classification': classification,
        'status':         '🚨 ATTACK' if predicted_attack else '✅ SUPPRESSED'
    }


def save_alerts(alerts):
    """Save last 200 alerts to JSON for dashboard."""
    recent = alerts[-200:]
    with open(ALERTS_JSON, 'w') as f:
        json.dump(recent, f, indent=2)


def calculate_metrics(alerts):
    """Calculate all 7 thesis metrics from ground truth."""
    if not alerts:
        return {}

    total    = len(alerts)
    tp       = sum(1 for a in alerts if a['classification'] == 'True Positive')
    tn       = sum(1 for a in alerts if a['classification'] == 'True Negative')
    fp       = sum(1 for a in alerts if a['classification'] == 'False Positive')
    fn       = sum(1 for a in alerts if a['classification'] == 'False Negative')

    accuracy  = round((tp + tn) / total * 100, 2) if total > 0 else 0
    precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0
    recall    = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0
    fpr       = round(fp / (fp + tn) * 100, 2) if (fp + tn) > 0 else 0
    f1        = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) > 0 else 0
    fp_reduction = round((1 - fpr / 100) * 100, 2)

    return {
        'total': total, 'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'accuracy': accuracy, 'precision': precision,
        'recall': recall, 'fpr': fpr, 'f1': f1,
        'fp_reduction': fp_reduction
    }


def print_live_stats(alerts, flow_id):
    """Print live metrics to terminal."""
    m = calculate_metrics(alerts)
    if not m:
        return

    print(f'\r[Flow {flow_id:5d}] '
          f'Accuracy: {m["accuracy"]:6.2f}% | '
          f'FPR: {m["fpr"]:5.2f}% | '
          f'Precision: {m["precision"]:6.2f}% | '
          f'Recall: {m["recall"]:6.2f}% | '
          f'FP reduced: {m["fp_reduction"]:5.2f}%     ',
          end='', flush=True)


def print_final_results(alerts, flow_id):
    """Print final thesis metrics."""
    m = calculate_metrics(alerts)
    if not m:
        return

    print(f'\n\n{"="*60}')
    print(f'  FINAL RESULTS — {flow_id-1} flows processed')
    print(f'{"="*60}')
    print(f'  True Positives  (attacks caught):    {m["tp"]:,}')
    print(f'  True Negatives  (normal suppressed): {m["tn"]:,}')
    print(f'  False Positives (normal flagged):    {m["fp"]:,}')
    print(f'  False Negatives (attacks missed):    {m["fn"]:,}')
    print(f'{"─"*60}')
    print(f'  Accuracy:        {m["accuracy"]}%')
    print(f'  Precision:       {m["precision"]}%')
    print(f'  Recall:          {m["recall"]}%')
    print(f'  F1 Score:        {m["f1"]}%')
    print(f'  False Positive Rate: {m["fpr"]}%')
    print(f'  FP Reduction:    {m["fp_reduction"]}%')
    print(f'{"="*60}')
    print(f'  Results saved → alerts.json')
    print(f'  Dashboard → http://localhost:5000')


def run_replay(delay=0.2):
    """Run unlimited replay loop."""
    print('=' * 60)
    print('  IDS Replay — Unlimited Traffic Simulation')
    print('  Stacked RF+XGBoost — Nepali Commercial Banks')
    print('=' * 60)
    print()

    rf_model, xgb_model, scaler = load_models()
    df, available = load_dataset()

    print(f'\n[*] Starting unlimited replay')
    print(f'[*] 80% normal + 20% attack per batch')
    print(f'[*] Delay: {delay}s per flow')
    print(f'[*] Dashboard: http://localhost:5000')
    print(f'[*] Press Ctrl+C to stop and see final results\n')

    alerts  = []
    flow_id = 1

    while True:
        try:
            X_batch, y_batch = get_random_batch(df, available, batch_size=50)

            for idx, (_, row) in enumerate(X_batch.iterrows()):
                label  = y_batch.iloc[idx]
                result = classify_flow(
                    row, label, rf_model, xgb_model, scaler, flow_id
                )
                alerts.append(result)
                save_alerts(alerts)
                print_live_stats(alerts, flow_id)
                flow_id += 1
                time.sleep(delay)

        except KeyboardInterrupt:
            print_final_results(alerts, flow_id)
            break
        except Exception as e:
            print(f'\n[!] Error on flow {flow_id}: {e}')
            flow_id += 1
            continue


if __name__ == '__main__':
    run_replay(delay=0.2)

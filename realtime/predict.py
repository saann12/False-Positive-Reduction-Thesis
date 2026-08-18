import warnings
warnings.filterwarnings('ignore')

"""
predict.py
Loads the stacked RF+XGBoost model and classifies
each mapped Suricata alert as real attack or false positive.
Includes deduplication — groups duplicate signatures.
"""

import json
import numpy as np
import joblib
import os
from datetime import datetime
from feature_mapping import map_all_alerts

# Paths
MODELS_PATH = os.path.join(os.path.dirname(__file__), '../models/')
ALERTS_JSON = os.path.join(os.path.dirname(__file__), 'alerts.json')

def load_models():
    """Load trained RF and stacked XGBoost models."""
    rf_model  = joblib.load(os.path.join(MODELS_PATH, 'random_forest_model.pkl'))
    xgb_model = joblib.load(os.path.join(MODELS_PATH, 'xgboost_stacked_model.pkl'))
    scaler    = joblib.load(os.path.join(MODELS_PATH, 'scaler.pkl'))
    print('[*] Models loaded successfully')
    return rf_model, xgb_model, scaler

def classify_alerts(mapped_alerts, rf_model, xgb_model, scaler):
    """Classify each alert using stacked model."""
    results = []
    for i, alert in enumerate(mapped_alerts):
        try:
            features        = np.array(alert['features']).reshape(1, -1)
            features_scaled = scaler.transform(features)

            # Stage 1 — Random Forest
            rf_prob = rf_model.predict_proba(features_scaled)[:, 1]

            # Stage 2 — Stacked XGBoost
            stacked    = np.column_stack([features_scaled, rf_prob])
            prediction = xgb_model.predict(stacked)[0]
            confidence = xgb_model.predict_proba(stacked)[0][1] * 100

            result = {
                'id':         i + 1,
                'timestamp':  alert['timestamp'],
                'src_ip':     alert['src_ip'],
                'dest_ip':    alert['dest_ip'],
                'proto':      alert['proto'],
                'signature':  alert['signature'],
                'is_attack':  bool(prediction == 1),
                'confidence': round(float(confidence), 1),
                'count':      alert.get('count', 1),
                'status':     'ATTACK' if prediction == 1 else 'SUPPRESSED'
            }
            results.append(result)

        except Exception as e:
            print(f'[!] Error classifying alert: {e}')

    return results

def deduplicate_results(results):
    """
    Group duplicate alerts by signature.
    Keep highest confidence result for each unique signature.
    Show count of how many times it occurred.
    """
    seen = {}
    for r in results:
        key = f"{r['signature']}_{r['src_ip']}"
        if key in seen:
            seen[key]['count'] += 1
            # Keep highest confidence
            if r['confidence'] > seen[key]['confidence']:
                seen[key]['confidence'] = r['confidence']
                seen[key]['is_attack']  = r['is_attack']
            seen[key]['last_seen'] = r['timestamp']
        else:
            seen[key] = r.copy()
            seen[key]['count']      = 1
            seen[key]['first_seen'] = r['timestamp']
            seen[key]['last_seen']  = r['timestamp']

    # Re-number IDs
    deduped = list(seen.values())
    for i, r in enumerate(deduped):
        r['id'] = i + 1

    return deduped

def print_summary(results, deduped):
    """Print classification summary."""
    total   = len(results)
    attacks = sum(1 for r in deduped if r['is_attack'])
    fp      = len(deduped) - attacks

    print(f'\n{"="*55}')
    print(f'  CLASSIFICATION SUMMARY')
    print(f'{"="*55}')
    print(f'  Total alerts processed:    {total}')
    print(f'  Unique signatures:         {len(deduped)}')
    print(f'  Real attacks:              {attacks}')
    print(f'  False positives suppressed:{fp}')
    if total > 0:
        print(f'  Suppression rate:          {round(fp/len(deduped)*100, 1)}%')
    print(f'{"="*55}')
    for r in deduped:
        status = '🚨 ATTACK' if r['is_attack'] else '✅ SUPPRESSED'
        count  = f"×{r['count']}" if r['count'] > 1 else ''
        print(f"  {status} {count} — {r['signature'][:45]} ({r['confidence']}%)")

def save_results(results):
    """Save classified results for dashboard."""
    with open(ALERTS_JSON, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\n[*] Results saved to alerts.json ({len(results)} entries)')

def run():
    print('[*] Loading models...')
    rf_model, xgb_model, scaler = load_models()

    print('[*] Mapping Suricata alerts to features...')
    mapped_alerts = map_all_alerts()

    if not mapped_alerts:
        print('[!] No alerts to classify')
        return

    print(f'[*] Classifying {len(mapped_alerts)} alerts...')
    results = classify_alerts(mapped_alerts, rf_model, xgb_model, scaler)

    # Deduplicate for dashboard
    deduped = deduplicate_results(results)

    print_summary(results, deduped)

    # Save deduplicated results to dashboard
    save_results(deduped)

if __name__ == '__main__':
    run()
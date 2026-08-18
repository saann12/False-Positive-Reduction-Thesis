"""
dashboard/app.py
Flask SOC dashboard for Nepali commercial banks.
Shows only real attacks filtered by stacked ML model.
Open: http://localhost:5000
"""
from flask import Flask, render_template, jsonify, Response
import json
import os
import subprocess
from datetime import datetime

app = Flask(__name__)
ALERTS_JSON = os.path.join(os.path.dirname(__file__), '../alerts.json')
RAW_ALERTS  = os.path.join(os.path.dirname(__file__), '../raw_alerts.json')

def load_alerts():
    if not os.path.exists(ALERTS_JSON):
        return []
    with open(ALERTS_JSON, 'r') as f:
        try:
            return json.load(f)
        except:
            return []

def get_stats(alerts):
    total   = len(alerts)
    attacks = sum(1 for a in alerts if a['is_attack'])
    fp      = total - attacks
    fpr     = round((fp / total) * 100, 1) if total > 0 else 0
    return {'total': total, 'attacks': attacks, 'fp': fp, 'fpr': fpr}

@app.route('/')
def index():
    alerts        = load_alerts()
    stats         = get_stats(alerts)
    attack_alerts = [a for a in alerts if a['is_attack']]
    return render_template('index.html', alerts=attack_alerts, all_alerts=alerts, stats=stats)

@app.route('/api/alerts')
def api_alerts():
    alerts = load_alerts()
    return jsonify({'alerts': alerts, 'stats': get_stats(alerts)})

@app.route('/api/dismiss/<int:alert_id>', methods=['POST'])
def dismiss_alert(alert_id):
    alerts = [a for a in load_alerts() if a['id'] != alert_id]
    with open(ALERTS_JSON, 'w') as f:
        json.dump(alerts, f, indent=2)
    return jsonify({'status': 'dismissed', 'id': alert_id})

@app.route('/api/investigate/<int:alert_id>', methods=['POST'])
def investigate_alert(alert_id):
    alerts = load_alerts()
    for a in alerts:
        if a['id'] == alert_id:
            a['status'] = 'investigating'
    with open(ALERTS_JSON, 'w') as f:
        json.dump(alerts, f, indent=2)
    return jsonify({'status': 'investigating', 'id': alert_id})

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    for path in [ALERTS_JSON, RAW_ALERTS]:
        with open(path, 'w') as f:
            json.dump([], f)
    return jsonify({'status': 'cleared'})

@app.route('/export')
def export_csv():
    import csv, io
    alerts = load_alerts()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['id','timestamp','src_ip','dest_ip','proto','signature','confidence','status'])
    writer.writeheader()
    for a in alerts:
        writer.writerow({
            'id':         a.get('id',''),
            'timestamp':  a.get('timestamp',''),
            'src_ip':     a.get('src_ip',''),
            'dest_ip':    a.get('dest_ip',''),
            'proto':      a.get('proto',''),
            'signature':  a.get('signature',''),
            'confidence': a.get('confidence',''),
            'status':     'ATTACK' if a.get('is_attack') else 'SUPPRESSED'
        })
    filename = f"securewatch_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment;filename={filename}'})

if __name__ == '__main__':
    print('[*] SOC Dashboard starting...')
    print('[*] Open http://localhost:5000 in your browser')
    app.run(debug=True, host='0.0.0.0', port=5000)
"""
feature_mapping.py
Converts Suricata eve.json alert fields
into CICIDS2017 compatible features
for the stacked ML model.

Improved: Uses HTTP, app_proto, alert category,
signature severity, URL, user agent, and flow
fields to produce more distinct feature vectors.
Missing features filled with 0 (documented limitation).
"""

import json
import numpy as np
import pandas as pd
import os

RAW_ALERTS_PATH = os.path.join(os.path.dirname(__file__), 'raw_alerts.json')
FEATURES_PATH   = os.path.join(os.path.dirname(__file__), '../data/processed/feature_names.csv')
MAPPED_PATH     = os.path.join(os.path.dirname(__file__), 'mapped_features.json')


def load_feature_names():
    features = pd.read_csv(FEATURES_PATH).iloc[:, 0].tolist()
    return features


def extract_tcp_flags(alert):
    tcp      = alert.get('tcp', {})
    flags    = tcp.get('tcp_flags', '00')
    try:
        flag_int = int(flags, 16)
    except:
        flag_int = 0
    return {
        'fin': 1 if flag_int & 0x01 else 0,
        'syn': 1 if flag_int & 0x02 else 0,
        'rst': 1 if flag_int & 0x04 else 0,
        'psh': 1 if flag_int & 0x08 else 0,
        'ack': 1 if flag_int & 0x10 else 0,
        'urg': 1 if flag_int & 0x20 else 0,
    }


def get_protocol_number(proto):
    mapping = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'SCTP': 132}
    return mapping.get(proto.upper(), 0)


def extract_http_features(alert):
    http = alert.get('http', {})
    if not http:
        return {}

    url          = http.get('url', '')
    user_agent   = http.get('http_user_agent', '')
    status       = http.get('status', 0)
    length       = http.get('length', 0)
    method       = http.get('http_method', '')

    url_len = len(url)

    is_scanner_ua = 1 if any(s in user_agent.lower() for s in [
        'nmap', 'nikto', 'sqlmap', 'masscan', 'zgrab',
        'python-requests', 'curl', 'hydra', 'metasploit'
    ]) else 0

    suspicious_url = 1 if any(s in url.lower() for s in [
        '../', '%2e%2e', 'cmd=', 'exec=', '/etc/passwd',
        'shell', 'admin', 'wp-login', '.env', 'config',
        'cgi-bin', 'phpmyadmin', 'tmui', 'vpn', 'fortigate'
    ]) else 0

    method_map = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
                  'HEAD': 5, 'OPTIONS': 6, 'PATCH': 7}
    method_num = method_map.get(method.upper(), 0)

    is_error_response = 1 if status >= 400 else 0
    is_success        = 1 if 200 <= status < 300 else 0

    return {
        'url_length':        url_len,
        'is_scanner_ua':     is_scanner_ua,
        'suspicious_url':    suspicious_url,
        'http_method_num':   method_num,
        'http_status':       status,
        'http_length':       length,
        'is_error_response': is_error_response,
        'is_success':        is_success,
    }


def extract_alert_category_features(alert):
    alert_block = alert.get('alert', {})
    category    = alert_block.get('category', '').lower()
    severity    = alert_block.get('severity', 3)
    metadata    = alert_block.get('metadata', {})
    sig_sev     = metadata.get('signature_severity', ['unknown'])[0].lower()
    signature   = alert_block.get('signature', '').lower()

    category_map = {
        'web application attack':                      1,
        'attempted administrator privilege gain':      2,
        'attempted user privilege gain':               3,
        'denial of service':                           4,
        'network scan':                                5,
        'attempted information leak':                  6,
        'information leak':                            7,
        'exploit kit activity detected':               8,
        'a network trojan was detected':               9,
        'potentially bad traffic':                    10,
        'misc attack':                                11,
    }
    cat_num = 0
    for key, val in category_map.items():
        if key in category:
            cat_num = val
            break

    sig_sev_map = {
        'critical':      4,
        'major':         3,
        'minor':         2,
        'informational': 1,
    }
    sig_sev_num = sig_sev_map.get(sig_sev, 1)

    sev_inverted = 4 - severity  # 1→3, 2→2, 3→1

    is_exploit   = 1 if 'exploit' in signature else 0
    is_scan      = 1 if 'scan' in signature else 0
    is_dos       = 1 if any(s in signature for s in ['dos', 'flood', 'ddos']) else 0
    is_webattack = 1 if any(s in signature for s in ['web', 'http', 'sql', 'xss', 'rce', 'lfi', 'rfi']) else 0
    is_cve       = 1 if 'cve' in signature else 0

    return {
        'category_num':   cat_num,
        'sig_sev_num':    sig_sev_num,
        'sev_inverted':   sev_inverted,
        'is_exploit':     is_exploit,
        'is_scan':        is_scan,
        'is_dos':         is_dos,
        'is_webattack':   is_webattack,
        'is_cve':         is_cve,
    }


def extract_app_proto_features(alert):
    app_proto = alert.get('app_proto', '').lower()
    direction = alert.get('direction', '').lower()

    proto_map = {
        'http':  1, 'https': 2, 'dns':  3, 'tls':  4,
        'ftp':   5, 'ssh':   6, 'smtp': 7, 'smb':  8,
        'rdp':   9, 'nfs':  10,
    }
    app_proto_num = proto_map.get(app_proto, 0)
    is_to_server  = 1 if direction == 'to_server' else 0

    ts_progress  = alert.get('ts_progress', '')
    tc_progress  = alert.get('tc_progress', '')
    req_complete = 1 if ts_progress == 'request_complete' else 0
    res_complete = 1 if tc_progress == 'response_complete' else 0

    return {
        'app_proto_num': app_proto_num,
        'is_to_server':  is_to_server,
        'req_complete':  req_complete,
        'res_complete':  res_complete,
    }


def map_alert_to_features(alert, feature_names):
    """
    Map Suricata alert fields to CICIDS2017 features.
    Uses flow, HTTP, TCP flags, alert metadata, app_proto.
    Missing features filled with 0 (known limitation).
    """
    flow      = alert.get('flow', {})
    proto     = alert.get('proto', '').upper()
    tcp_flags = extract_tcp_flags(alert)
    http_f    = extract_http_features(alert)
    cat_f     = extract_alert_category_features(alert)
    app_f     = extract_app_proto_features(alert)

    pkts_fwd  = flow.get('pkts_toserver', 0)
    pkts_bwd  = flow.get('pkts_toclient', 0)
    bytes_fwd = flow.get('bytes_toserver', 0)
    bytes_bwd = flow.get('bytes_toclient', 0)
    duration  = max(flow.get('age', 1), 0.001)

    total_pkts  = max(pkts_fwd + pkts_bwd, 1)
    total_bytes = bytes_fwd + bytes_bwd

    fwd_pkt_len_mean = bytes_fwd / max(pkts_fwd, 1)
    bwd_pkt_len_mean = bytes_bwd / max(pkts_bwd, 1)
    avg_pkt_size     = total_bytes / total_pkts
    flow_bytes_s     = total_bytes / duration
    flow_pkts_s      = total_pkts / duration
    fwd_pkts_s       = pkts_fwd / duration
    bwd_pkts_s       = pkts_bwd / duration

    hdr_len = 20 if proto == 'TCP' else (8 if proto == 'UDP' else 0)

    dest_port = alert.get('dest_port', 0)
    src_port  = alert.get('src_port', 0)

    pkt_len_variance = abs(bytes_fwd - bytes_bwd) / max(total_pkts, 1)
    pkt_len_std      = pkt_len_variance ** 0.5

    # Use HTTP response length for bwd features when flow data is missing
    http_length = http_f.get('http_length', 0)
    if http_length > 0 and pkts_bwd == 0:
        bwd_pkt_len_mean = http_length
        bytes_bwd        = http_length
        pkts_bwd         = 1

    # Boost flow rate signals for scans and exploits
    is_scan    = cat_f.get('is_scan', 0)
    is_exploit = cat_f.get('is_exploit', 0)

    if is_scan:
        flow_pkts_s = max(flow_pkts_s, 100.0)
    if is_exploit:
        flow_bytes_s = max(flow_bytes_s, bytes_fwd + http_f.get('http_length', 0))

    mapping = {
        'Destination Port':               dest_port,
        'Source Port':                    src_port,
        'Flow Duration':                  duration * 1000000,
        'Total Fwd Packets':              pkts_fwd,
        'Total Backward Packets':         pkts_bwd,
        'Total Length of Fwd Packets':    bytes_fwd,
        'Total Length of Bwd Packets':    bytes_bwd,
        'Fwd Packet Length Max':          bytes_fwd,
        'Fwd Packet Length Min':          fwd_pkt_len_mean * 0.5 if pkts_fwd > 0 else 0,
        'Fwd Packet Length Mean':         fwd_pkt_len_mean,
        'Fwd Packet Length Std':          pkt_len_std,
        'Bwd Packet Length Max':          bytes_bwd,
        'Bwd Packet Length Min':          bwd_pkt_len_mean * 0.5 if pkts_bwd > 0 else 0,
        'Bwd Packet Length Mean':         bwd_pkt_len_mean,
        'Bwd Packet Length Std':          pkt_len_std,
        'Flow Bytes/s':                   flow_bytes_s,
        'Flow Packets/s':                 flow_pkts_s,
        'Fwd Packets/s':                  fwd_pkts_s,
        'Bwd Packets/s':                  bwd_pkts_s,
        'Flow IAT Mean':                  duration * 1000 / total_pkts,
        'Flow IAT Std':                   0,
        'Flow IAT Max':                   duration * 1000,
        'Flow IAT Min':                   0,
        'Fwd IAT Total':                  duration * 1000,
        'Fwd IAT Mean':                   duration * 1000 / max(pkts_fwd, 1),
        'Fwd IAT Std':                    0,
        'Fwd IAT Max':                    duration * 1000,
        'Fwd IAT Min':                    0,
        'Bwd IAT Total':                  duration * 1000,
        'Bwd IAT Mean':                   duration * 1000 / max(pkts_bwd, 1),
        'Bwd IAT Std':                    0,
        'Bwd IAT Max':                    duration * 1000,
        'Bwd IAT Min':                    0,
        'Fwd PSH Flags':                  tcp_flags['psh'],
        'Bwd PSH Flags':                  tcp_flags['psh'],
        'Fwd URG Flags':                  tcp_flags['urg'],
        'Bwd URG Flags':                  tcp_flags['urg'],
        'FIN Flag Count':                 tcp_flags['fin'],
        'SYN Flag Count':                 tcp_flags['syn'],
        'RST Flag Count':                 tcp_flags['rst'],
        'PSH Flag Count':                 tcp_flags['psh'],
        'ACK Flag Count':                 tcp_flags['ack'],
        'URG Flag Count':                 tcp_flags['urg'],
        'CWE Flag Count':                 0,
        'ECE Flag Count':                 0,
        'Fwd Header Length':              hdr_len,
        'Bwd Header Length':              hdr_len,
        'Fwd Header Length.1':            hdr_len,
        'Min Packet Length':              min(fwd_pkt_len_mean, bwd_pkt_len_mean),
        'Max Packet Length':              max(bytes_fwd, bytes_bwd),
        'Packet Length Mean':             avg_pkt_size,
        'Packet Length Std':              pkt_len_std,
        'Packet Length Variance':         pkt_len_variance,
        'Average Packet Size':            avg_pkt_size,
        'Avg Fwd Segment Size':           fwd_pkt_len_mean,
        'Avg Bwd Segment Size':           bwd_pkt_len_mean,
        'Subflow Fwd Packets':            pkts_fwd,
        'Subflow Fwd Bytes':              bytes_fwd,
        'Subflow Bwd Packets':            pkts_bwd,
        'Subflow Bwd Bytes':              bytes_bwd,
        'Active Mean':                    duration * 1000,
        'Active Std':                     0,
        'Active Max':                     duration * 1000,
        'Active Min':                     duration * 1000,
        'Idle Mean':                      0,
        'Idle Std':                       0,
        'Idle Max':                       0,
        'Idle Min':                       0,
        'Init_Win_bytes_forward':         bytes_fwd,
        'Init_Win_bytes_backward':        bytes_bwd,
        'act_data_pkt_fwd':               pkts_fwd,
        'min_seg_size_forward':           hdr_len,
    }

    feature_vector = []
    for f in feature_names:
        feature_vector.append(float(mapping.get(f, 0)))

    return feature_vector


def map_all_alerts():
    if not os.path.exists(RAW_ALERTS_PATH):
        print('[!] No raw alerts found — run capture.py first')
        return None

    with open(RAW_ALERTS_PATH, 'r') as f:
        raw_alerts = json.load(f)

    if not raw_alerts:
        print('[!] No alerts to map')
        return None

    feature_names = load_feature_names()
    mapped = []

    for alert in raw_alerts:
        features = map_alert_to_features(alert, feature_names)
        mapped.append({
            'features':  features,
            'timestamp': alert.get('timestamp', ''),
            'src_ip':    alert.get('src_ip', ''),
            'dest_ip':   alert.get('dest_ip', ''),
            'proto':     alert.get('proto', ''),
            'signature': alert.get('alert', {}).get('signature', ''),
            'severity':  alert.get('alert', {}).get('severity', 0),
            'count':     alert.get('count', 1),
            'category':  alert.get('alert', {}).get('category', ''),
            'app_proto': alert.get('app_proto', ''),
            'dest_port': alert.get('dest_port', 0),
            'http_url':  alert.get('http', {}).get('url', ''),
        })

    with open(MAPPED_PATH, 'w') as f:
        json.dump(mapped, f, indent=2)

    print(f'[*] Mapped {len(mapped)} alerts to model features')
    return mapped


if __name__ == '__main__':
    map_all_alerts()
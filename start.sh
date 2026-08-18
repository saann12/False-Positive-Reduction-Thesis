#!/bin/bash
clear
echo "================================================"
echo "  IDS False Positive Reduction System"
echo "  Nepali Commercial Banks"
echo "================================================"
echo ""

# Check Suricata
if ! systemctl is-active --quiet suricata; then
    echo "[*] Starting Suricata..."
    sudo systemctl start suricata
    sleep 3
fi
echo "✅ Suricata running"

# Open browser automatically
sleep 3 && firefox http://localhost:5000 &
echo "✅ Browser opening..."

# Start pipeline
echo "✅ Starting pipeline..."
echo ""
cd ~/thesis/realtime
python3 run.py

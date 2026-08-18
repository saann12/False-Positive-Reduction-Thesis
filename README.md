# Stacked ML Post-Alert Classification for Suricata IDS

A post-alert classification module that sits between Suricata IDS and a SOC analyst, using a two-stage stacked ensemble (Random Forest + XGBoost) to filter false positives out of DoS/DDoS-category alerts before they reach the analyst queue. Built as part of a BSc cybersecurity thesis for Nepali commercial bank SOC environments.

## What this does

- Trains a stacked Random Forest + XGBoost classifier on labelled DoS/DDoS network flows (CICIDS2017 dataset)
- Reads Suricata's `eve.json` alert output, maps it to the model's feature space, and classifies each alert as a genuine threat or false positive
- Presents filtered results through **SecureWatch**, a Flask-based analyst dashboard with SHAP-based explainability

## Repository structure

```
notebooks/           Model development pipeline, run in order:
  01_data_exploration.ipynb   Explore CICIDS2017 dataset structure
  02_preprocessing.ipynb      Clean data, feature scale, train/test split
  03_baseline.ipynb           Establish rule-based Suricata baseline
  04_random_forest.ipynb      Train and evaluate standalone Random Forest
  05_xgboost_stacked.ipynb    Train XGBoost on RF's out-of-fold predictions
  06_comparison.ipynb         Compare baseline vs RF vs stacked model

models/               Pre-trained model artifacts (included, ~10MB total)
  random_forest_model.pkl
  xgboost_stacked_model.pkl
  scaler.pkl

realtime/              Live pipeline
  capture.py            Captures/reads live Suricata alert traffic
  feature_mapping.py    Maps Suricata eve.json fields to model features
  predict.py             Loads trained models and classifies incoming alerts
  replay.py               Replays captured traffic for testing
  run.py                    Orchestrates the real-time pipeline
  dashboard/
    app.py                 SecureWatch Flask dashboard
    templates/index.html

results/
  figures/     Confusion matrices, ROC curves, SHAP plots, comparison charts
  metrics/     Cross-validation results and summary metrics (CSV)

start.sh       Convenience script to launch the pipeline/dashboard
```

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Option A — Use the pre-trained models (fastest)

The trained models in `models/` are ready to use. To run the real-time pipeline against live Suricata alerts:

```bash
./start.sh
```

This requires a running Suricata instance producing `eve.json` output that `realtime/capture.py` can read. Verify the paths inside `capture.py` and `run.py` match your Suricata log location before running.

### Option B — Retrain from scratch

1. Download the CICIDS2017 dataset (DoS/DDoS-category files) from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) and place the CSVs in `data/raw/`.
2. Run the notebooks in order: `01` → `02` → `03` → `04` → `05` → `06`.
3. This regenerates `data/processed/` and `models/`.

## Results

Trained and evaluated on labelled DoS/DDoS-category network flows from CICIDS2017. See `results/metrics/results_summary.csv` and `results/figures/` for full evaluation figures (confusion matrices, ROC curves, SHAP explainability plots).

**Scope note:** the model is trained and evaluated on DoS/DDoS-category traffic only (Hulk, GoldenEye, Slowloris, Slowhttptest, DDoS, Heartbleed). It reduces false positives among Suricata alerts in this category — it is not a general-purpose false-positive filter across all Suricata alert types.

## Known limitation

Real-time testing revealed a domain gap: individual exploit probe alerts, though correctly flagged by Suricata's content-based detection, can produce flow statistics resembling benign traffic and get suppressed by the model. This is documented in the thesis and partially mitigated through confidence scoring and SHAP-based explainability, with final decision authority always retained by the human analyst.

## Author

Sanil Gurung (saann) — BSc Cybersecurity, Softwarica College of IT & E-Commerce (affiliated with Coventry University)

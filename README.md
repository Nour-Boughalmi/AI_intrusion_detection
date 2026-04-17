# Cloud Intrusion Detection System (IDS)

An AI-powered hybrid Intrusion Detection System designed to analyze multiple log sources in a cloud environment and identify malicious activity. The system combines supervised and unsupervised machine learning approaches to cover both known threats and zero-day anomalies.

> Academic project — PFA, ENETCOM Sfax

---

## Project Structure

```
IDS4/
├── Non supervisé/
│   ├── Dashboard/             # Unsupervised visualization dashboards
│   ├── Data/                  # Raw datasets (Application, System, Cloud logs)
│   ├── Models/                # Trained unsupervised models
│   └── Notebooks/             # Jupyter notebooks: application.ipynb, cloud.ipynb, system.ipynb
│
├── Supervisé/
│   ├── dashboard/             # Supervised visualization dashboards
│   ├── data/                  # Labeled datasets (TCP, Auth, Network/CICIDS)
│   ├── models/                # Trained supervised models
│   └── notebooks/             # Jupyter notebooks: labelstcp.ipynb, logs_authentification.ipynb, network_logs.ipynb
│
├── models/                    # Production models loaded by the Flask app
│   ├── tcp_rf.pkl / tcp_xgboost_final.pkl / tcp_scaler.pkl
│   ├── auth_random_forest.pkl
│   ├── network_cnn.h5 / network_scaler.pkl / network_label_encoder.pkl
│   ├── app_isolation_forest.pkl / app_scaler.pkl
│   ├── cloud_isolation_forest.pkl / cloud_scaler.pkl
│   └── system_lof.pkl / system_scaler.pkl
│
├── templates/                 # Jinja2 HTML templates
├── static/                    # CSS / static assets
├── app.py                     # Flask dashboard + AI chatbot (Groq)
├── api.py                     # FastAPI real-time prediction endpoint
├── alerter.py                 # Email alerting (Gmail SMTP)
├── correlation.py             # Cross-log IP correlation engine
├── config.py                  # Configuration constants
├── Dockerfile                 # Docker image definition
├── requirements.txt
└── README.md
```

---

## ML Models & Approaches

### Supervised Learning — Known Threat Detection

| Log Source | Model | Performance |
|---|---|---|
| TCP | XGBoost (optimized) | 99% accuracy |
| TCP | Random Forest | 93.6% accuracy |
| TCP | MLP | 89% accuracy |
| Authentication | Random Forest + SMOTE | Handles 96%/4% class imbalance |
| Network | 1D CNN (13 attack classes) | 99.09% accuracy |

**Detected threats:** Port Scan, DDoS, DoS, FTP-Patator, SSH-Patator, Brute Force, SQL Injection, XSS, Bot, Heartbleed, Credential Stuffing

### Unsupervised Learning — Anomaly / Zero-Day Detection

| Log Source | Model | Anomalies Detected |
|---|---|---|
| Application | Isolation Forest (contamination=0.2) | 1 584 / 7 934 events |
| Cloud AWS | Isolation Forest (contamination=0.1) | 193 920 / 1 939 207 events |
| System (Windows) | LOF (n_neighbors=50) | 2 923 / 14 613 events |

**Detected threats:** Privilege escalation, unauthorized S3 access, rootkit persistence, Schannel crypto errors, behavioral anomalies

---

## Scale

| Metric | Value |
|---|---|
| Total events analyzed | 2,097,227 |
| Suspicious events detected | 27,642 |
| Suspicious IPs identified | 56 |
| Alert levels | NORMAL / MEDIUM / HIGH |

---

## Dashboard & Features

- **Live dashboard** — event statistics, alert distribution, suspicious IP table
- **IP correlation engine** — cross-references the same IP across all 6 log sources to assign a danger level (LOW / MEDIUM / HIGH / CRITICAL)
- **AI security chatbot** — powered by Groq (LLM), answers analyst questions about the IDS results in context
- **Real-time prediction API** — `/predict` endpoint accepts JSON, runs the appropriate model, returns an alert level, and sends an email if HIGH
- **Automated email alerts** — Gmail SMTP integration via `alerter.py`

### Danger Level Classification

| Level | Condition |
|---|---|
| LOW | IP appears in 1 log only |
| MEDIUM | IP appears in 2 logs |
| HIGH | IP in 2+ logs with at least 1 HIGH alert |
| CRITICAL | IP in 3+ logs with at least 2 HIGH alerts |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 / Flask / FastAPI |
| ML | scikit-learn, XGBoost, TensorFlow (CNN 1D) |
| Visualization | Plotly, Jinja2 |
| AI Chatbot | Groq API |
| Alerting | Gmail SMTP |
| Containerization | Docker |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Nour-Boughalmi/ids_cloud_detection
cd IDS4

# 2. Create a virtual environment
conda create -n IDS python=3.11
conda activate IDS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env: add your GROQ_API_KEY and Gmail credentials
```

### Run locally

```bash
python app.py
# Dashboard available at http://localhost:5000
```

### Run with Docker

```bash
docker build -t ids4 .
docker run -p 5000:5000 --env-file .env ids4
```

---

## Real-Time Prediction API

The FastAPI service (`api.py`) exposes a `/predict` endpoint:

```bash
POST /predict
Content-Type: application/json

{
  "log_type": "tcp",
  "features": [...]
}
```

Response: `{ "alert": "HIGH" | "MEDIUM" | "NORMAL" }`

An email is automatically dispatched when the alert level is `HIGH`.

---

## Known Limitations

- Independent datasets → no CRITICAL IPs detected (no IP overlap across logs)
- Real-time API covers only 3 of the 6 log types (TCP, Auth, Cloud)
- No authentication on the dashboard
- Auth dataset is synthetic and small (1,000 rows)
- 1D CNN misses SQL Injection (0% recall) and XSS (3% recall)

---

## Dependencies

See [requirements.txt](requirements.txt) for the full list. Key packages:

```
flask, fastapi, plotly, pandas, numpy,
scikit-learn, xgboost, tensorflow, joblib,
groq, python-dotenv, scipy
```

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify
import pandas as pd
import plotly.express as px
import os
import joblib
import numpy as np
from datetime import datetime
from alerter import envoyer_alerte_email
from groq import Groq

SYSTEM_PROMPT = """Tu es un assistant de sécurité intégré au système IDS hybride
développé dans le cadre d'un projet PFA à ENETCOM Sfax.

TON RÔLE :
Tu aides l'administrateur de sécurité à comprendre et analyser
les résultats de détection d'intrusions affichés dans le dashboard.
Tu réponds de façon concise, professionnelle et en français.

LE SYSTÈME IDS :
- Analyse 6 sources de logs : TCP, Auth, Network, Application, Cloud, System
- 2 097 227 événements analysés au total
- 27 642 événements suspects détectés
- 56 IPs suspectes identifiées
- 3 niveaux d'alerte : NORMAL, MEDIUM, HIGH

LES MODÈLES ML UTILISÉS :
Logs supervisés :
- TCP : fusion de 5 modèles — Decision Tree 77%, SVM 69%, MLP 89%,
  Random Forest 93.6%, XGBoost optimisé 99%
- Auth : Random Forest + XGBoost avec SMOTE (déséquilibre 96%/4%)
- Network : CNN 1D avec 99.09% accuracy sur 13 classes d'attaques

Logs non supervisés :
- Application : Isolation Forest contamination=0.2 → 1584 anomalies / 7934
- Cloud AWS : Isolation Forest contamination=0.1 → 193 920 anomalies / 1 939 207
- System Windows : LOF n_neighbors=50 → 2923 anomalies / 14 613

LES MENACES PAR LOG :
- TCP : scan de ports, DDoS
- Auth : brute force, credential stuffing
- Network : DDoS, PortScan, SQL Injection, XSS, Bot, Heartbleed
- Cloud AWS : escalade de privilèges, accès non autorisé S3
- System : rootkit, persistance, erreurs cryptographiques Schannel
- Application : anomalies comportementales, erreurs répétées

IPs LES PLUS SUSPECTES :
- 172.16.1.24 → 6095 alertes HIGH → TCP — score risque 3051.77
- 172.16.1.28 → 5148 alertes HIGH → TCP — score risque 2578.34
- 192.168.0.10 → 4754 alertes HIGH → TCP — score risque 2381.24
- 192.168.203.193 → 1 alerte HIGH → Auth
- 192.168.199.215 → 1 alerte HIGH → Auth

NIVEAUX DE DANGER :
- FAIBLE : IP dans 1 seul log
- MOYEN : IP dans 2 logs
- ÉLEVÉ : IP dans 2+ logs avec au moins 1 HIGH
- CRITIQUE : IP dans 3+ logs avec au moins 2 HIGH

RÉSULTATS DE LA CORRÉLATION :
- Toutes les 56 IPs sont FAIBLE car les datasets sont indépendants
- Pas d'IPs communes entre les 6 logs
- Dans un environnement réel, des IPs CRITIQUES seraient détectées

API TEMPS RÉEL :
- Route /predict → reçoit un JSON → modèle → HIGH/MEDIUM/NORMAL
- Email automatique si HIGH
- 3 logs intégrés : TCP, Auth, Cloud
- Simulateur automatique toutes les heures

STACK TECHNIQUE :
Python 3.13, Flask, Plotly, Jinja2, scikit-learn,
TensorFlow, XGBoost, Docker 29.3.1, Gmail SMTP

LIMITES CONNUES :
- Datasets indépendants → 0 IP CRITIQUE
- API temps réel couvre seulement 3 logs sur 6
- Pas d'authentification sur le dashboard
- Dataset Auth synthétique et trop petit (1000 lignes)
- CNN 1D rate SQL Injection (0% rappel) et XSS (3% rappel)

RÈGLES DE RÉPONSE :
- Toujours répondre en français
- Être concis et professionnel
- Si on te demande de bloquer une IP → expliquer que tu es en lecture seule
- Si on te pose une question hors contexte IDS → recentrer poliment
- Ne jamais inventer des données que tu ne connais pas
"""

app = Flask(__name__)

# ── Charger les modèles ────────────────────────────────────────
BASE_MODELS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

modeles = {}
try:
    modeles["tcp_rf"]     = joblib.load(os.path.join(BASE_MODELS, "tcp_rf.pkl"))
    modeles["tcp_scaler"] = joblib.load(os.path.join(BASE_MODELS, "tcp_scaler.pkl"))
    modeles["auth_rf"]    = joblib.load(os.path.join(BASE_MODELS, "auth_random_forest.pkl"))
    modeles["cloud_if"]   = joblib.load(os.path.join(BASE_MODELS, "cloud_isolation_forest.pkl"))
    modeles["cloud_sc"]   = joblib.load(os.path.join(BASE_MODELS, "cloud_scaler.pkl"))
    modeles["system_lof"] = joblib.load(os.path.join(BASE_MODELS, "system_lof.pkl"))
    modeles["system_sc"]  = joblib.load(os.path.join(BASE_MODELS, "system_scaler.pkl"))
    print("✅ Tous les modèles chargés")
except Exception as e:
    print(f"⚠️  Certains modèles non chargés : {e}")

def load_data():
    base        = os.path.dirname(os.path.abspath(__file__))
    df_corr     = pd.read_csv(os.path.join(base, "correlation_report.csv"))
    df_suspects = pd.read_csv(os.path.join(base, "all_suspects.csv"))
    return df_corr, df_suspects

# ── Dashboard ──────────────────────────────────────────────────
@app.route("/")
def dashboard():
    df_corr, df_suspects = load_data()

    total_events    = 2_097_227
    total_suspects  = len(df_suspects)
    total_ips       = len(df_corr)
    total_critiques = len(df_corr[df_corr["danger"].str.contains("CRITIQUE", na=False)])
    total_eleves    = len(df_corr[df_corr["danger"].str.contains("ÉLEVÉ",    na=False)])

    colors = {
        "🔴 CRITIQUE" : "#E24B4A",
        "🟠 ÉLEVÉ"    : "#EF9F27",
        "🟡 MOYEN"    : "#639922",
        "🟢 FAIBLE"   : "#1D9E75",
    }

    danger_counts = df_corr["danger"].value_counts().reset_index()
    danger_counts.columns = ["danger", "count"]

    fig_danger = px.bar(
        danger_counts, x="danger", y="count",
        color="danger", color_discrete_map=colors,
        title="Distribution des niveaux de danger",
        labels={"danger": "Niveau", "count": "Nombre d'IPs"},
    )
    fig_danger.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False, font=dict(size=13),
    )

    source_counts = df_suspects["log_source"].value_counts().reset_index()
    source_counts.columns = ["log_source", "count"]

    fig_source = px.pie(
        source_counts, names="log_source", values="count",
        title="Répartition des alertes par log",
        color_discrete_sequence=px.colors.qualitative.Set2,
    )
    fig_source.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    top_ips = df_corr.nlargest(10, "nb_high")
    fig_ips = px.bar(
        top_ips, x="source_ip", y="nb_high",
        color="danger", color_discrete_map=colors,
        title="Top 10 IPs — nombre d'alertes HIGH",
        labels={"source_ip": "Adresse IP", "nb_high": "Alertes HIGH"},
    )
    fig_ips.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False, xaxis_tickangle=-45,
    )

    graph_danger = fig_danger.to_json()
    graph_source = fig_source.to_json()
    graph_ips    = fig_ips.to_json()

    top20 = df_corr.head(20)[[
        "source_ip", "danger", "nb_logs_touches",
        "logs_touches", "nb_high", "risque_global"
    ]].to_dict("records")

    return render_template(
        "dashboard.html",
        total_events    = f"{total_events:,}",
        total_suspects  = f"{total_suspects:,}",
        total_ips       = f"{total_ips:,}",
        total_critiques = total_critiques,
        total_eleves    = total_eleves,
        graph_danger    = graph_danger,
        graph_source    = graph_source,
        graph_ips       = graph_ips,
        top20           = top20,
    )

# ── Prédiction temps réel ──────────────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data       = request.get_json()
        log_source = data.get("log_source", "unknown")
        source_ip  = data.get("source_ip",  "unknown")

        alert_level   = "NORMAL"
        anomaly_score = 0.0

        # ── TCP ───────────────────────────────────────────────
        if log_source == "tcp" and "tcp_rf" in modeles:
            features = np.array([[
                data.get("size",       0),
                data.get("sourcePort", 0),
                data.get("destPort",   0),
                data.get("seqNumber",  0),
                data.get("ackNumber",  0),
                data.get("flags",      0),
                data.get("fragmented", 0),
                data.get("hour",       datetime.now().hour),
                data.get("dayofweek",  datetime.now().weekday()),
            ]])
            score         = modeles["tcp_rf"].predict_proba(features)[0][1]
            anomaly_score = float(score)
            alert_level   = ("HIGH"   if score >= 0.7 else
                             "MEDIUM" if score >= 0.3 else "NORMAL")

        # ── Auth ──────────────────────────────────────────────
        elif log_source == "auth" and "auth_rf" in modeles:
            features = np.array([[
                data.get("Response_Time_ms",      0),
                data.get("Anomaly_Score",         0),
                data.get("Request_Type_encoded",  0),
                data.get("is_slow_response",      0),
                data.get("is_high_anomaly",       0),
                data.get("ip_first_octet",        0),
                data.get("ip_second_octet",       0),
                data.get("ip_third_octet",        0),
                data.get("ip_last_octet",         0),
            ]])
            score         = modeles["auth_rf"].predict_proba(features)[0][1]
            anomaly_score = float(score)
            alert_level   = ("HIGH"   if score >= 0.7 else
                             "MEDIUM" if score >= 0.3 else "NORMAL")

        # ── Cloud ─────────────────────────────────────────────
        elif log_source == "cloud" and "cloud_if" in modeles:
            features = np.array([[
                data.get("hour",                     0),
                data.get("day_of_week",              0),
                data.get("month",                    0),
                data.get("is_error",                 0),
                data.get("eventName_encoded",        0),
                data.get("eventSource_encoded",      0),
                data.get("userAgent_encoded",        0),
                data.get("errorCode_encoded",        0),
                data.get("sourceIPAddress_encoded",  0),
                data.get("userIdentitytype_encoded", 0),
                data.get("awsRegion_encoded",        0),
            ]])
            features_scaled = modeles["cloud_sc"].transform(features)
            pred            = modeles["cloud_if"].predict(features_scaled)[0]
            score           = modeles["cloud_if"].decision_function(features_scaled)[0]
            anomaly_score   = float(score)
            alert_level     = "HIGH" if pred == -1 else "NORMAL"

        # ── Email si HIGH ─────────────────────────────────────
        email_envoye = False
        if alert_level == "HIGH":
            email_envoye = envoyer_alerte_email(
                source_ip     = source_ip,
                log_source    = log_source,
                alert_level   = alert_level,
                anomaly_score = anomaly_score,
                details       = data
            )

        return jsonify({
            "status"        : "success",
            "timestamp"     : datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "source_ip"     : source_ip,
            "log_source"    : log_source,
            "alert_level"   : alert_level,
            "anomaly_score" : round(anomaly_score, 4),
            "email_envoye"  : email_envoye,
            "message"       : f"Alerte {alert_level} détectée depuis {source_ip}"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ── Chatbot ───────────────────────────────────────────────────
@app.route("/chat", methods=["POST"])
def chat():
    try:
        data     = request.get_json()
        user_msg = (data.get("message") or "").strip()
        history  = data.get("history", [])

        if not user_msg:
            return jsonify({"status": "error", "message": "Message vide"}), 400

        # Construire les messages : system + historique + nouveau message
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for m in history[-10:]:
            role    = m.get("role")
            content = m.get("content", "")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": user_msg})

        client   = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model       = "llama-3.1-8b-instant",
            messages    = messages,
            max_tokens  = 1024,
            temperature = 0.3,
        )
        reply = response.choices[0].message.content or ""

        return jsonify({"status": "success", "response": reply})

    except Exception as e:
        msg = str(e)
        if "invalid_api_key" in msg or "401" in msg or "Authentication" in msg:
            friendly = "Clé API invalide. Vérifiez GROQ_API_KEY dans le fichier .env"
        elif "429" in msg or "rate_limit" in msg.lower():
            friendly = "Limite de requêtes atteinte. Réessayez dans quelques secondes."
        else:
            friendly = msg
        return jsonify({"status": "error", "message": friendly}), 500

# ── Test email ─────────────────────────────────────────────────
@app.route("/test-email")
def test_email():
    resultat = envoyer_alerte_email(
        source_ip     = "192.168.1.5",
        log_source    = "tcp",
        alert_level   = "HIGH",
        anomaly_score = 0.94,
        details       = {"test": True}
    )
    return "✅ Email envoyé !" if resultat else "❌ Erreur email"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
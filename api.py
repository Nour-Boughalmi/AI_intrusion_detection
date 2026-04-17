from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import joblib
import numpy as np
import pandas as pd
import json
import os
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (Conv1D, BatchNormalization, MaxPooling1D,
                                      Dropout, Flatten, Dense)

app = FastAPI(title="IDS API", description="API de détection d'intrusions")

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

# ── Reconstruction manuelle du CNN ───────────────────────────
with open(os.path.join(BASE, "network_info.json"), "r") as f:
    info = json.load(f)

N_FEATURES = info["n_features"]
N_CLASSES  = info["n_classes"]

def build_cnn(n_features, n_classes):
    model = Sequential([
        Conv1D(64, 3, activation='relu', padding='same',
               input_shape=(n_features, 1)),
        BatchNormalization(),
        MaxPooling1D(2),
        Dropout(0.3),
        Conv1D(128, 3, activation='relu', padding='same'),
        BatchNormalization(),
        MaxPooling1D(2),
        Dropout(0.3),
        Conv1D(64, 3, activation='relu', padding='same'),
        BatchNormalization(),
        Dropout(0.3),
        Flatten(),
        Dense(128, activation='relu'),
        Dropout(0.4),
        Dense(64, activation='relu'),
        Dense(n_classes, activation='softmax')
    ])
    return model

network_model = build_cnn(N_FEATURES, N_CLASSES)
network_model.load_weights(os.path.join(BASE, "network_cnn_weights.weights.h5"))
print("✅ CNN chargé avec succès")

# ── Chargement des autres modèles ────────────────────────────
models = {
    "cloud": {
        "model" : joblib.load(os.path.join(BASE, "cloud_isolation_forest.pkl")),
        "scaler": joblib.load(os.path.join(BASE, "cloud_scaler.pkl"))
    },
    "app": {
        "model" : joblib.load(os.path.join(BASE, "app_isolation_forest.pkl")),
        "scaler": joblib.load(os.path.join(BASE, "app_scaler.pkl"))
    },
    "system": {
        "model" : joblib.load(os.path.join(BASE, "system_lof.pkl")),
        "scaler": joblib.load(os.path.join(BASE, "system_scaler.pkl"))
    },
    "tcp": {
        "model" : joblib.load(os.path.join(BASE, "tcp_xgboost.pkl")),
        "scaler": joblib.load(os.path.join(BASE, "tcp_scaler.pkl"))
    },
    "auth": {
        "model" : joblib.load(os.path.join(BASE, "auth_random_forest.pkl")),
        "scaler": None
    },
    "network": {
        "model"  : network_model,
        "scaler" : joblib.load(os.path.join(BASE, "network_scaler.pkl")),
        "encoder": joblib.load(os.path.join(BASE, "network_label_encoder.pkl"))
    }
}

# ── Features attendues par modèle ────────────────────────────
FEATURES = {
    "cloud"  : ["sourcePort","destPort","size","fragmented",
                 "seqNumber","ackNumber","flags","hour"],
    "app"    : ["Response_Time_ms","Anomaly_Score","ip_first_octet",
                 "ip_second_octet","ip_third_octet","ip_last_octet",
                 "Request_Type_encoded","is_slow_response","is_high_anomaly"],
    "system" : ["Level","Source","Event ID"],
    "tcp"    : ["sourcePort","destPort","size","fragmented",
                 "seqNumber","ackNumber","flags","hour"],
    "auth"   : ["Response_Time_ms","Anomaly_Score","ip_first_octet",
                 "ip_second_octet","ip_third_octet","ip_last_octet",
                 "Request_Type_encoded","is_slow_response","is_high_anomaly"],
    "network": ["sourcePort","destPort","size","fragmented",
                 "seqNumber","ackNumber","flags","hour"]
}

# ── Schéma d'entrée ──────────────────────────────────────────
class LogInput(BaseModel):
    source              : str
    sourcePort          : Optional[float] = None
    destPort            : Optional[float] = None
    size                : Optional[float] = None
    fragmented          : Optional[float] = None
    seqNumber           : Optional[float] = None
    ackNumber           : Optional[float] = None
    flags               : Optional[float] = None
    hour                : Optional[float] = None
    Response_Time_ms    : Optional[float] = None
    Anomaly_Score       : Optional[float] = None
    ip_first_octet      : Optional[float] = None
    ip_second_octet     : Optional[float] = None
    ip_third_octet      : Optional[float] = None
    ip_last_octet       : Optional[float] = None
    Request_Type_encoded: Optional[float] = None
    is_slow_response    : Optional[float] = None
    is_high_anomaly     : Optional[float] = None

# ── Gestion des attributs manquants ─────────────────────────
def prepare_input(data: dict, source: str):
    features = FEATURES[source]
    row      = {}
    missing  = []
    for f in features:
        val = data.get(f, None)
        if val is None:
            row[f] = 0.0
            missing.append(f)
        else:
            row[f] = float(val)
    df = pd.DataFrame([row])[features]
    return df, missing

# ── Endpoint principal ───────────────────────────────────────
@app.post("/predict")
def predict(log: LogInput):
    source = log.source.lower()

    if source not in models:
        return {
            "error": f"Source inconnue : '{source}'. "
                     f"Choisir parmi : {list(models.keys())}"
        }

    data = log.dict()
    data.pop("source")
    df_input, missing = prepare_input(data, source)

    try:
        scaler = models[source]["scaler"]
        model  = models[source]["model"]
        X = scaler.transform(df_input) if scaler is not None else df_input.values

        if source in ["cloud", "app", "system"]:
            pred  = model.predict(X)[0]
            label = "anomaly" if pred == -1 else "normal"
            alert = "HIGH" if label == "anomaly" else "NORMAL"
            return {
                "source"           : source,
                "prediction"       : label,
                "alert_level"      : alert,
                "missing_features" : missing,
                "status"           : "⚠️ attributs manquants" if missing else "✅ complet"
            }

        elif source in ["tcp", "auth"]:
            pred  = int(model.predict(X)[0])
            proba = float(model.predict_proba(X)[0][1])
            label = "attack" if pred == 1 else "benign"
            alert = "HIGH" if pred == 1 else "NORMAL"
            return {
                "source"           : source,
                "prediction"       : label,
                "proba_attack"     : round(proba, 4),
                "alert_level"      : alert,
                "missing_features" : missing,
                "status"           : "⚠️ attributs manquants" if missing else "✅ complet"
            }

        elif source == "network":
            try:
                encoder = models[source]["encoder"]
                X_cnn   = X.reshape(1, N_FEATURES, 1)
                proba   = network_model.predict(X_cnn, verbose=0)[0]
                idx     = int(np.argmax(proba))
                label   = encoder.inverse_transform([idx])[0]
                alert   = "NORMAL" if label == "BENIGN" else "HIGH"
                return {
                    "source"           : source,
                    "prediction"       : label,
                    "alert_level"      : alert,
                    "missing_features" : missing,
                    "status"           : "⚠️ attributs manquants" if missing else "✅ complet"
                }
            except Exception as e:
                return {"error": f"Erreur CNN : {str(e)}"}

    except Exception as e:
        return {"error": str(e)}

# ── Endpoints utilitaires ────────────────────────────────────
@app.get("/")
def root():
    return {"message": "IDS API opérationnelle 🛡️"}

@app.get("/sources")
def get_sources():
    return {"sources_disponibles": list(models.keys())}

@app.get("/features/{source}")
def get_features(source: str):
    if source not in FEATURES:
        return {"error": f"Source inconnue : {source}"}
    return {
        "source"  : source,
        "features": FEATURES[source]
    }
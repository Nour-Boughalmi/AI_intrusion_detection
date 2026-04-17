import pandas as pd
import numpy as np
import os

print("=" * 60)
print("SYSTÈME DE CORRÉLATION DES LOGS IDS")
print("=" * 60)

# ============================================================
# ÉTAPE 1 — Charger les 6 fichiers normalisés
# ============================================================
print("\n📂 Chargement des fichiers normalisés...\n")

base_sup  = r"C:\Users\asus\Desktop\IDS\Supervisé\notebooks\outputs"
base_nsup = r"C:\Users\asus\Desktop\IDS\Non supervisé\Notebooks\outputs"

fichiers = {
    "tcp"         : os.path.join(base_sup,  "tcp_output_normalized.csv"),
    "auth"        : os.path.join(base_sup,  "auth_output_normalized.csv"),
    "network"     : os.path.join(base_sup,  "network_output_normalized.csv"),
    "application" : os.path.join(base_nsup, "application_output_normalized.csv"),
    "cloud"       : os.path.join(base_nsup, "cloud_output_normalized.csv"),
    "system"      : os.path.join(base_nsup, "system_output_normalized.csv"),
}

dfs = []
for nom, chemin in fichiers.items():
    if os.path.exists(chemin):
        df_temp = pd.read_csv(chemin)
        df_temp["log_source"] = nom
        dfs.append(df_temp)
        print(f"   ✅ {nom:15s} → {len(df_temp):>8,} lignes")
    else:
        print(f"   ❌ {nom:15s} → fichier introuvable")

# ============================================================
# ÉTAPE 2 — Fusionner
# ============================================================
print("\n🔀 Fusion de tous les logs...")

colonnes_communes = [
    "timestamp", "source_ip", "log_source",
    "anomaly_score", "alert_level"
]

dfs_reduits = []
for df in dfs:
    cols_dispo = [c for c in colonnes_communes if c in df.columns]
    dfs_reduits.append(df[cols_dispo])

df_global = pd.concat(dfs_reduits, ignore_index=True)
print(f"   ✅ DataFrame global : {len(df_global):,} lignes")

# ============================================================
# ÉTAPE 3 — Nettoyage
# ============================================================
print("\n🧹 Préparation pour la corrélation...")

# Convertir alert_level en score
alert_map = {"HIGH": 3, "MEDIUM": 2, "NORMAL": 1}
df_global["alert_score"] = df_global["alert_level"].map(alert_map).fillna(1)

# IMPORTANT — Exclure les IPs "unknown" car elles faussent les résultats
df_avec_ip = df_global[
    ~df_global["source_ip"].isin(["unknown", "Unknown", ""])
].copy()

df_suspects = df_avec_ip[
    df_avec_ip["alert_level"].isin(["HIGH", "MEDIUM"])
].copy()

print(f"   ✅ Événements avec IP réelle    : {len(df_avec_ip):,}")
print(f"   ✅ Événements suspects avec IP  : {len(df_suspects):,}")

# ============================================================
# ÉTAPE 4 — Corrélation par IP
# ============================================================
print("\n🔗 Corrélation par source IP...\n")

if len(df_suspects) == 0:
    print("   ⚠️  Pas assez d'IPs réelles pour corréler.")
    print("   → Exécute d'abord les notebooks TCP et Auth")
    print("     pour générer les fichiers normalisés manquants.")
else:
    correlation_ip = df_suspects.groupby("source_ip").agg(
        nb_logs_touches = ("log_source", "nunique"),
        logs_touches    = ("log_source", lambda x: list(x.unique())),
        nb_alertes      = ("alert_level", "count"),
        nb_high         = ("alert_level", lambda x: (x == "HIGH").sum()),
        score_moyen     = ("alert_score", "mean"),
    ).reset_index()

    # Score de risque global
    correlation_ip["risque_global"] = (
        correlation_ip["nb_logs_touches"] * 1.5 +
        correlation_ip["nb_high"] * 0.5 +
        correlation_ip["score_moyen"] * 1.0
    ).round(2)

    # Niveau de danger
    def niveau_danger(row):
        if row["nb_logs_touches"] >= 3 and row["nb_high"] >= 2:
            return "🔴 CRITIQUE"
        elif row["nb_logs_touches"] >= 2 and row["nb_high"] >= 1:
            return "🟠 ÉLEVÉ"
        elif row["nb_logs_touches"] >= 2:
            return "🟡 MOYEN"
        else:
            return "🟢 FAIBLE"

    correlation_ip["danger"] = correlation_ip.apply(niveau_danger, axis=1)
    correlation_ip = correlation_ip.sort_values(
        "risque_global", ascending=False
    ).reset_index(drop=True)

    # ============================================================
    # ÉTAPE 5 — Affichage
    # ============================================================
    print("=" * 60)
    print("RÉSULTATS DE LA CORRÉLATION")
    print("=" * 60)

    print(f"\n📊 Statistiques globales :")
    print(f"   - Total événements analysés : {len(df_global):,}")
    print(f"   - Avec IP réelle            : {len(df_avec_ip):,}")
    print(f"   - Événements suspects       : {len(df_suspects):,}")
    print(f"   - IPs uniques suspectes     : {len(correlation_ip):,}")

    print(f"\n📈 Distribution des niveaux de danger :")
    print(correlation_ip["danger"].value_counts().to_string())

    critiques = correlation_ip[
        correlation_ip["danger"] == "🔴 CRITIQUE"
    ]
    if len(critiques) > 0:
        print(f"\n🚨 IPs CRITIQUES détectées :\n")
        for _, row in critiques.head(10).iterrows():
            print(f"   IP : {str(row['source_ip'])}")
            print(f"        Danger       : {row['danger']}")
            print(f"        Logs touchés : {row['nb_logs_touches']}"
                  f" → {row['logs_touches']}")
            print(f"        Alertes HIGH : {row['nb_high']}")
            print(f"        Risque       : {row['risque_global']}")
            print()
    else:
        print(f"\n⚠️  Aucune IP CRITIQUE — les datasets sont indépendants.")
        print(f"   C'est normal car nos logs viennent de sources différentes.")
        print(f"   Dans un vrai système, les mêmes IPs apparaîtraient")
        print(f"   dans plusieurs logs simultanément.")

        print(f"\n🚨 Top 5 IPs les plus suspectes quand même :\n")
        for _, row in correlation_ip.head(5).iterrows():
            print(f"   IP : {str(row['source_ip'])}")
            print(f"        Danger       : {row['danger']}")
            print(f"        Logs touchés : {row['nb_logs_touches']}"
                  f" → {row['logs_touches']}")
            print(f"        Alertes HIGH : {row['nb_high']}")
            print()

    # ============================================================
    # ÉTAPE 6 — Sauvegarde
    # ============================================================
    print("\n💾 Sauvegarde des résultats...")
    output_dir = r"C:\Users\asus\Desktop\IDS"

    correlation_ip.to_csv(
        os.path.join(output_dir, "correlation_report.csv"), index=False
    )
    print(f"   ✅ correlation_report.csv sauvegardé")

    df_suspects.to_csv(
        os.path.join(output_dir, "all_suspects.csv"), index=False
    )
    print(f"   ✅ all_suspects.csv sauvegardé")

print("\n" + "=" * 60)
print("✅ CORRÉLATION TERMINÉE")
print("=" * 60)
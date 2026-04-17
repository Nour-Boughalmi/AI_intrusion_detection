import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import config

def envoyer_alerte_email(source_ip, log_source, alert_level, anomaly_score, details=None):
    """
    Envoie un email d'alerte quand une intrusion est détectée.
    """
    if alert_level != "HIGH":
        return False

    try:
        # ── Construire le message ──────────────────────────────
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[IDS ALERTE] Intrusion détectée — {log_source.upper()} — {source_ip}"
        msg["From"]    = config.EMAIL_SENDER
        msg["To"]      = config.EMAIL_RECEIVER

        # ── Corps du message HTML ──────────────────────────────
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">

            <div style="background:#E24B4A; color:white; padding:16px;
                        border-radius:8px; margin-bottom:20px;">
                <h2 style="margin:0">ALERTE INTRUSION DÉTECTÉE</h2>
                <p style="margin:4px 0 0">Système IDS — Détection en temps réel</p>
            </div>

            <table style="width:100%; border-collapse:collapse;">
                <tr style="background:#f4f5f7;">
                    <td style="padding:10px; font-weight:bold;">Heure de détection</td>
                    <td style="padding:10px;">{datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td style="padding:10px; font-weight:bold;">Adresse IP suspecte</td>
                    <td style="padding:10px; color:#E24B4A; font-weight:bold;">{source_ip}</td>
                </tr>
                <tr style="background:#f4f5f7;">
                    <td style="padding:10px; font-weight:bold;">Source du log</td>
                    <td style="padding:10px;">{log_source.upper()}</td>
                </tr>
                <tr>
                    <td style="padding:10px; font-weight:bold;">Niveau d'alerte</td>
                    <td style="padding:10px;">
                        <span style="background:#E24B4A; color:white;
                                     padding:4px 12px; border-radius:4px;">
                            {alert_level}
                        </span>
                    </td>
                </tr>
                <tr style="background:#f4f5f7;">
                    <td style="padding:10px; font-weight:bold;">Score d'anomalie</td>
                    <td style="padding:10px;">{round(anomaly_score, 4)}</td>
                </tr>
                {"<tr><td style='padding:10px; font-weight:bold;'>Détails</td><td style='padding:10px;'>" + str(details) + "</td></tr>" if details else ""}
            </table>

            <div style="background:#FAEEDA; padding:12px; border-radius:8px;
                        margin-top:20px; border-left:4px solid #EF9F27;">
                <strong>Action recommandée :</strong>
                Vérifiez immédiatement l'activité de l'IP {source_ip}
                et bloquez-la si nécessaire.
            </div>

            <p style="color:#888; font-size:12px; margin-top:20px;">
                Ce message a été généré automatiquement par le système IDS.
            </p>

        </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        # ── Envoyer via Gmail SMTP ─────────────────────────────
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(config.EMAIL_SENDER, config.EMAIL_PASSWORD)
            server.sendmail(
                config.EMAIL_SENDER,
                config.EMAIL_RECEIVER,
                msg.as_string()
            )

        print(f"✅ Email d'alerte envoyé pour IP {source_ip}")
        return True

    except Exception as e:
        print(f"❌ Erreur envoi email : {e}")
        return False
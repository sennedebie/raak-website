# ════════════════════════════════════════════════
# ▶ IMPORTS
# ════════════════════════════════════════════════

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ════════════════════════════════════════════════
# ▶ EMAIL FUNCTIONS
# ════════════════════════════════════════════════

def send_admin_email(subject, body, reply_to=None):
    ''' Send email to admin via SMTP server '''
    sender_email = "sennedebiechristmas@gmail.com"
    sender_password = "eqwr wpjj pndu etei"
    recipient_email = "sennedebie@icloud.com"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)

def send_simple_email(to_email, subject, body):
    """ Send mail via SMTP server to user (confirmation) """
    sender_email = "sennedebiechristmas@gmail.com"
    sender_password = "eqwr wpjj pndu etei"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception:
        pass  # Silently ignore confirmation mail errors

def send_confirmation_email(to_email, name, form_type):
    """ Send confirmation mail for form submissions """
    if form_type == "contact":
        subject = "Bevestiging van je contactaanvraag bij Raak Leerbeek-Kester"
        body = f"""Beste {name},

Bedankt voor je bericht aan Raak Leerbeek-Kester. We hebben je vraag of opmerking goed ontvangen en nemen zo snel mogelijk contact met je op.

Met vriendelijke groeten,
Het Raak Leerbeek-Kester team
"""
    elif form_type == "membership":
        subject = "Bevestiging van je lidmaatschapsaanvraag bij Raak Leerbeek-Kester"
        body = f"""Beste {name},

Bedankt voor je aanvraag om lid te worden van Raak Leerbeek-Kester. We hebben je aanvraag goed ontvangen en nemen spoedig contact met je op.

Met vriendelijke groeten,
Het Raak Leerbeek-Kester team
"""
    else:
        return

    send_simple_email(to_email, subject, body)

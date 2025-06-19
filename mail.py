# ════════════════════════════════════════════════
# ▶ IMPORTS
# ════════════════════════════════════════════════

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ════════════════════════════════════════════════
# ▶ MAIL ALIASES (concept)
# ════════════════════════════════════════════════

# info@raakleerbeekkester.be -> Algemeen e-mailadres
# communicatie@raakleerbeekkester.be -> Pers en communicatie
# leden@raakleerbeekkester.be -> Ledenadministratie


# ════════════════════════════════════════════════
# ▶ SMTP SERVER CONFIG
# ════════════════════════════════════════════════

smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_sender_email = "sennedebiechristmas@gmail.com" # All outgoing mails will be send with this adress
smtp_sender_password = "fdux pfge gaty hsfw"


# ════════════════════════════════════════════════
# ▶ EMAIL FUNCTIONS
# ════════════════════════════════════════════════



def send_admin_email(subject, body, reply_to=None):
    ''' Send email to admin via SMTP server '''

    msg = MIMEMultipart()
    msg["From"] = smtp_sender_email
    msg["To"] = forms_recipient_email
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_sender_email, smtp_sender_password)
            server.sendmail(smtp_sender_email, forms_recipient_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def send_simple_email(to_email, subject, body):
    """ Send mail via SMTP server to user (confirmation) """

    msg = MIMEMultipart()
    msg["From"] = smtp_sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_sender_email, smtp_sender_password)
            server.sendmail(smtp_sender_email, to_email, msg.as_string())
    except Exception:
        pass  # Silently ignore confirmation mail errors


def send_login_credentials_email(to_email, first_name, username, token):
    '''' Send login credentials to newly registered user '''
    subject = "Welkom bij Raak Leerbeek-Kester!"
    body = f"""Beste {first_name},

    Er werd voor jou een gebruikersaccount aangemaakt voor de website van Raak Leerbeek-Kester.
    Met deze logingegevens kan je inloggen via www.raakleerbeekkester.be/login . 
    Vul de toegangscode in als wachtwoord, bij de eerst log in zal je gevraagd om een wachtwoord in te stellen.

    Gebruikersnaam: {username}
    Eenmalige toegangscode: {token}


    Met vriendelijke groeten,
    Het Raak Leerbeek-Kester team

"""
    send_simple_email(to_email, subject, body)


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

def get_contact_mail_content(firstname, lastname, email, message):
    subject = "Website Raak-Leerbeek: nieuw contactformulier"
    body = f"""
Je hebt een nieuwe vraag of opmerking:

Name: {firstname} {lastname}
Email: {email}
Message:
{message}
"""
    return subject, body

def get_membership_mail_content(firstname, lastname, email, phone, gsm, street, city, zip_code, membership_type, message):
    subject = "Website Raak-Leerbeek: nieuw lidmaatschap"
    body = f"""
Nieuwe lidmaatschapsaanvraag:

Naam: {firstname} {lastname}
Email: {email}
Telefoonnummer: {phone}
GSM-nummer: {gsm}
Straat + huisnummer: {street}
Stad/gemeente: {city}
Postcode: {zip_code}
Type lidmaatschap: {membership_type}
Bericht:
{message}
"""
    return subject, body

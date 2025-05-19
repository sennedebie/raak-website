# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import os
from werkzeug.utils import secure_filename


# Initialize Flask app
app = Flask(__name__)
app.secret_key = "qs989hkjdlq98!skw/o"  # Required for flash messages

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'static/uploads' # Folder to store uploaded files
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Create the folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # Set the upload folder in the app config
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # Allowed file extensions

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ROUTES ---

@app.route("/")
def index():
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route("/nieuws", endpoint="news")
def news():
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    conn.close()
    return render_template('news.html', posts=posts)

@app.route('/admin')
def admin():
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    conn.close()
    return render_template('admin.html', posts=posts)

@app.route('/admin/add', methods=['GET', 'POST'])
def add_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        date = request.form['date']

        image_file = request.files.get('image')  # Get uploaded file
        filename = None

        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
        else:
            flash('Alleen afbeeldingen zijn toegestaan (jpg, jpeg, png, gif)', 'danger')
            return redirect(request.url)

        # Save all data including image filename
        conn = sqlite3.connect('database/posts.db')
        conn.execute('INSERT INTO posts (title, content, category, date, image_filename) VALUES (?, ?, ?, ?, ?)',
                     (title, content, category, date, filename))
        conn.commit()
        conn.close()

        flash('Bericht toegevoegd!', 'success')
        return redirect(url_for('admin'))

    return render_template('add_edit_post.html', form_title='Nieuw Bericht', post=None)

@app.route('/admin/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        date = request.form['date']

        image_file = request.files.get('image')
        filename = post['image_filename']  # Default to the old one

        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                # Delete the old image file
                if post['image_filename']:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename'])
                    if os.path.exists(old_path):
                        os.remove(old_path)

                # Save new image
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            else:
                flash('Alleen afbeeldingen zijn toegestaan (jpg, jpeg, png, gif)', 'danger')
                return redirect(request.url)

        # Update the database
        conn.execute('UPDATE posts SET title=?, content=?, category=?, date=?, image_filename=? WHERE id=?',
                     (title, content, category, date, filename, post_id))
        conn.commit()
        conn.close()

        flash('Bericht bijgewerkt!', 'success')
        return redirect(url_for('admin'))

    return render_template('add_edit_post.html', form_title='Bewerk Bericht', post=post)

@app.route('/admin/delete/<int:post_id>')
def delete_post(post_id):
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if post and post['image_filename']:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename'])
        if os.path.exists(image_path):
            os.remove(image_path)  # delete the image file

    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()

    flash('Bericht en afbeelding verwijderd!', 'info')
    return redirect(url_for('admin'))

@app.route("/agenda", endpoint="agenda")
def agenda():
    return render_template("agenda.html")

@app.route("/lid-worden", endpoint="membership")
def membership():
    return render_template("membership.html")

@app.route("/contact", endpoint="contact")
def contact():
    return render_template("contact.html")

@app.route("/contact-form-submit", methods=["POST"])
def contact_submit_form():
    # Get form data
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    message = request.form.get("message")

    subject = "Website Raak-Leerbeek: nieuw contactformulier"
    body = f"""
    Je hebt een nieuwe vraag of opmerking:
    
    Name: {firstname} {lastname}
    Email: {email}
    Message:
    {message}
    """

    success, error = send_email(subject, body, reply_to=email)
    if success:
        flash("We hebben jouw bericht goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "contact")
    else:
        flash(f"Er is een fout opgetreden!: {error}", "danger")

    return redirect(url_for("contact"))

@app.route("/membership-form-submit", methods=["POST"])
def membership_submit_form():
    # Get membership form data
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    phone = request.form.get("phone")
    gsm = request.form.get("gsm")
    street = request.form.get("street")
    city = request.form.get("city")
    zip_code = request.form.get("zip")
    membership_type = request.form.get("membership_type")
    message = request.form.get("message")

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

    success, error = send_email(subject, body, reply_to=email)
    if success:
        flash("We hebben je aanvraag goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "membership")
    else:
        flash(f"Er is een fout opgetreden: {error}", "danger")

    return redirect(url_for("membership"))

# --- FUNCTIONS ---

def send_email(subject, body, reply_to=None):
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
    """ Send mail via SMTP server"""
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

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
# --------------------
# IMPORTS & SETUP
# --------------------
import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authentication.database import get_db_connection
from mail import send_admin_email, send_confirmation_email

# --------------------
# FLASK APP CONFIG
# --------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # from .env

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    ''' Check if the file is allowed '''
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------
# FLASK-LOGIN SETUP
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirects to /login if not logged in

# --------------------
# USER LOADER
# --------------------
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            return User(user[0], user[1], user[2])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --------------------
# ROLE-BASED ACCESS CONTROL
# --------------------
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not hasattr(current_user, "role") or current_user.role not in roles:
                flash("Je hebt geen toegang tot deze pagina.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --------------------
# GENERAL ROUTES
# --------------------
@app.route("/")
def index():
    ''' Fetch latest posts from database and render index page '''
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC LIMIT 6').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route("/nieuws", endpoint="news")
def news():
    ''' Fetch all posts from database and render news page '''
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    conn.close()
    return render_template('news.html', posts=posts)

@app.route("/agenda", endpoint="agenda")
def agenda():
    ''' Render agenda page '''
    return render_template("agenda.html")

@app.route("/lid-worden", endpoint="membership")
def membership():
    ''' Render membership page '''
    return render_template("membership.html")

@app.route("/contact", endpoint="contact")
def contact():
    ''' Render contact page '''
    return render_template("contact.html")

# --------------------
# SPECIAL ROUTES: REGISTER & LOGIN
# --------------------
@app.route("/register", methods=["GET", "POST"], endpoint="register")
def register():
    ''' Handle user registration '''
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "user")  # Default: 'user'

        if not username or not password:
            flash("Gebruikersnaam en wachtwoord zijn vereist.")
            return redirect("/register")

        # Explicitly set the method to avoid scrypt issues
        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed_pw, role))
            conn.commit()
        except Exception:
            conn.rollback()
            flash("Gebruikersnaam reeds in gebruik.", "warning")
            return redirect("/register")
        finally:
            cur.close()
            conn.close()

        flash("Registratie gelukt. Je kan nu inloggen!")
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    '''Login route for users'''
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1], user[3])
            login_user(user_obj)
            flash("Login successful.")
            next_page = request.args.get("next")
            if user[3] in ("admin", "author"):
                # Redirect to next page if present, else to author
                return redirect(next_page or url_for("author"))
            elif user[3] in ("member"):
                return redirect(next_page or url_for("index"))
            else:
                flash("Je hebt geen toegang tot het auteursgedeelte.", "warning")
                return redirect(next_page or url_for("index"))
        else:
            flash("Invalid credentials.")
            return redirect("/login")

    return render_template("login.html")

@app.route("/logout", endpoint="logout")
@app.route("/logout", endpoint="logout")
@login_required
def logout():
    ''' Logout route for users '''
    logout_user()
    flash("You have been logged out.")
    return redirect("/login")
# --------------------
# SPECIAL ROUTES: AUTHOR & ADMIN
# --------------------

@app.route('/author', endpoint="author")
@role_required('admin', 'author')
def author():
    ''' Admin page to manage website content '''
    conn = sqlite3.connect('database/posts.db')
    conn.row_factory = sqlite3.Row
    posts = conn.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    conn.close()
    return render_template('author.html', posts=posts)

@app.route('/author/add', methods=['GET', 'POST'])
@role_required('admin', 'author')
def add_post():
    ''' Add new post to database '''
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
        return redirect(url_for('author'))

    return render_template('add_edit_post.html', form_title='Nieuw Bericht', post=None)

@app.route('/author/edit/<int:post_id>', methods=['GET', 'POST'])
@role_required('admin', 'author')
def edit_post(post_id):
    ''' Edit existing post in database '''
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
        return redirect(url_for('author'))

    return render_template('add_edit_post.html', form_title='Bewerk Bericht', post=post)

@app.route('/author/delete/<int:post_id>')
@role_required('admin', 'author')
def delete_post(post_id):
    ''' Delete post from database '''
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
    return redirect(url_for('author'))

# --------------------
# FORM HANDLERS
# --------------------
@app.route("/contact-form-submit", methods=["POST"])
def contact_submit_form():
    ''' Handle contact form submission '''
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

    success, error = send_admin_email(subject, body, reply_to=email)
    if success:
        flash("We hebben jouw bericht goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "contact")
    else:
        flash(f"Er is een fout opgetreden!: {error}", "danger")

    return redirect(url_for("contact"))

@app.route("/membership-form-submit", methods=["POST"])
def membership_submit_form():
    ''' Handle membership form submission '''
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

    success, error = send_admin_email(subject, body, reply_to=email)
    if success:
        flash("We hebben je aanvraag goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "membership")
    else:
        flash(f"Er is een fout opgetreden: {error}", "danger")

    return redirect(url_for("membership"))


# --------------------
# MAIN ENTRY POINT
# --------------------
if __name__ == "__main__":
    app.run(debug=True)
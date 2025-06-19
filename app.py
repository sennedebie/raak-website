# ════════════════════════════════════════════════
# ▶ IMPORTS
# ════════════════════════════════════════════════
import os
import re
import random
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database.db_connection import get_db_connection
from mail import *
from dotenv import load_dotenv
from datetime import datetime, timezone



# ════════════════════════════════════════════════
# ▶ LOAD VARIABLES
# ════════════════════════════════════════════════

# Load environment variables from .env file (for development deployment only)
load_dotenv()


# ════════════════════════════════════════════════
# ▶ INITIATE FLASK APP
# ════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Use your .env secret
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Log in om deze pagina te bekijken."
login_manager.login_message_category = "warning"

# ════════════════════════════════════════════════
# ▶ USER MODEL
# ════════════════════════════════════════════════
class User(UserMixin):
    def __init__(self, id, username, first_name, last_name, roles, permissions, is_active=True):
        '''
        Constructor to initialize user object.
        
        Called upon instantiation of a user object
        (e.g. new user registration, login, request from Flask-Login).
        '''

        self.id = id
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.roles = roles  # List of role names
        self.permissions = permissions  # List of permission names
        self._is_active = is_active  # Use a private attribute


    @property
    def is_active(self):
        return self._is_active

    @staticmethod
    def get(user_id):
        '''
        Fetch user object from database.
        
        Used in Flask-Login to load current user from session, 
        so that every request has access to user's roles, permissions and active status.
        '''

        conn = get_db_connection()
        try:
            cur = conn.cursor()

            # Fetch user record form database, including require_password_change
            cur.execute("SELECT id, username, first_name, last_name, is_active, require_password_change FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                return None
            
            # Get all roles for this user
            cur.execute("""
                SELECT r.name FROM roles r
                JOIN user_role_map urm ON r.id = urm.role_id
                WHERE urm.user_id = %s
            """, (user_id,))
            roles = [row['name'] for row in cur.fetchall()]

            # Get all permissions for this user
            cur.execute("""
                SELECT DISTINCT p.name FROM permissions p
                JOIN role_permission_map rpm ON p.id = rpm.permission_id
                JOIN user_role_map urm ON rpm.role_id = urm.role_id
                WHERE urm.user_id = %s
            """, (user_id,))
            permissions = [row['name'] for row in cur.fetchall()]

        finally:
            cur.close()
            conn.close()

        # Return user object, attach require_password_change as attribute
        user_obj = User(user["id"], user["username"], user["first_name"], user["last_name"], roles, permissions, user["is_active"])
        user_obj.require_password_change = user.get("require_password_change", False)
        return user_obj
    


@login_manager.user_loader
def load_user(user_id):
    '''
    Load user from database by id for Flask-Login.
    
    Called by Flask-Login when authentication is required
    (e.g. route decorators)
    '''
    return User.get(user_id)


# ════════════════════════════════════════════════
# ▶ ROLE BASED ACCESS CONTROL
# ════════════════════════════════════════════════

def role_required(*roles):
    """
    Decorator to restrict access to routes based on user roles.

    This decorator ensures that the current user is authenticated, active,
    and has at least one of the specified roles. If the user does not meet
    these criteria, they are redirected to the index page with an error message.

    Usage:
        @role_required('admin', 'editor')
        def protected_route():
            ...

    Args:
        *roles: One or more role names (as strings) that are allowed to access the route.

    Returns:
        The decorated function, which will only execute if the user has the required role(s).
    """
    
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if (
                current_user is None or not hasattr(current_user, "roles")
                or not any(role in current_user.roles for role in roles)
                or current_user is None
                or not getattr(current_user, "is_active", False)
            ):
                flash("Je hebt geen toegang tot deze pagina.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required(*permissions):
    """
    Decorator to restrict access to routes based on user permissions.

    This decorator ensures that the current user is authenticated, active,
    and has at least one of the specified permissions. If the user does not meet
    these criteria, they are redirected to the index page with an error message.

    Usage:
        @permission_required('edit_post', 'delete_post')
        def protected_route():
            ...

    Args:
        *permissions: One or more permission names (as strings) that are allowed to access the route.

    Returns:
        The decorated function, which will only execute if the user has the required permission(s).
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if (
                not hasattr(current_user, "permissions")
                or not any(p in current_user.permissions for p in permissions)
                or not getattr(current_user, "is_active", False)
            ):
                flash("Je hebt geen toegang tot deze pagina.", "danger")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ════════════════════════════════════════════════
# ▶ INDEX PAGE
# ════════════════════════════════════════════════

@app.route("/", endpoint="index")
def index():
    ''' 
    Home page.
    
    Fetch recent posts from database and render page.
    '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT p.*, pi.url AS image_url
    FROM posts p
    LEFT JOIN post_images pi ON p.id = pi.post_id
    WHERE p.is_pinned = %s and pi.is_main = %s
    ORDER BY p.created_at DESC
    LIMIT 1""", (True, True))
    posts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('public/index.html', posts=posts)


# ════════════════════════════════════════════════
# ▶ NEWS PAGE
# ════════════════════════════════════════════════

@app.route("/nieuws", endpoint="news")
def news():
    '''
    News page.
    
    Fetch all posts from database and render page
    '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM posts ORDER BY is_pinned DESC, created_at DESC')
    posts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('public/news.html', posts=posts)


# ════════════════════════════════════════════════
# ▶ AGENDA PAGE
# ════════════════════════════════════════════════

@app.route("/agenda", endpoint="agenda")
def agenda():
    ''' Agenda page '''
    return render_template("public/agenda.html")


# ════════════════════════════════════════════════
# ▶ MEMBERSHIP PAGE
# ════════════════════════════════════════════════

@app.route("/lid-worden", endpoint="membership")
def membership():
    ''' Membership page '''
    return render_template("public/membership.html")


# ════════════════════════════════════════════════
# ▶ ABOUT US PAGE
# ════════════════════════════════════════════════

@app.route("/over-ons", endpoint="about")
def about_us():
    '''
    About us page.
    
    Fetch board members from database and render page.
    '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username, u.function, u.about_me
        FROM users u
        JOIN user_role_map urm ON u.id = urm.user_id
        JOIN roles r ON r.id = urm.role_id
            WHERE r.name = %s 
              AND u.is_active = %s
        """, ('bestuurslid', True)
        )
    board_members = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("public/about_us.html", board_members=board_members)


# ════════════════════════════════════════════════
# ▶ CONTACT PAGE
# ════════════════════════════════════════════════

@app.route("/contact", endpoint="contact")
def contact():
    ''' Contact page '''
    return render_template("public/contact.html")


# ════════════════════════════════════════════════
# ▶ LOGIN
# ════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    '''Login route for users'''

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, is_active, require_password_change  FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Check if user exists in database
        if not user:
            flash("Ongeldige logingegevens.", "danger")
            return redirect(url_for("login"))
        # Check provided password against hash stored in database
        if user and check_password_hash(user["password_hash"], password):

            if not user["is_active"]:
                flash("Gebruiker is niet actief.", "danger")
                return redirect(url_for("login"))
            # Use User.get to fetch roles and permissions
            user_obj = User.get(user["id"])

            if user_obj is None:
                flash("Gebruiker niet gevonden.", "warning")
                return redirect(url_for("login"))

            if user["require_password_change"]:
                login_user(user_obj)
                return redirect(url_for("set_password"))
            
            login_user(user_obj)
            return redirect(url_for("dashboard"))

        else:
            flash("Ongeldige logingegevens.", "danger")
            return redirect(url_for("login"))

    return render_template("public/login.html")

# ════════════════════════════════════════════════
# ▶ SET PASSWORD (UPON FIRST LOGIN)
# ════════════════════════════════════════════════

@app.route("/wachtwoord-instellen", methods=["GET", "POST"], endpoint="set_password")
def set_password():
    ''' Set password upon first login '''
    if not current_user.is_authenticated:
        flash("Je moet ingelogd zijn om je wachtwoord in te stellen.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = %s", (current_user.id,))
    user_row = cur.fetchone()
    cur.close()
    conn.close()
    username = user_row["username"] if user_row else ""

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not password or not confirm_password:
            flash("Vul beide wachtwoordvelden in.", "danger")
            return render_template("admin/set_password.html", username=username)

        if password != confirm_password:
            flash("Wachtwoorden komen niet overeen.", "danger")
            return render_template("admin/set_password.html", username=username)

        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s, require_password_change = %s WHERE id = %s",
            (password_hash, False, current_user.id)
        )
        conn.commit()
        cur.close()
        conn.close()
        flash("Wachtwoord succesvol ingesteld. Je kunt nu verder.", "success")
        return redirect(url_for("dashboard"))
    return render_template("admin/set_password.html", username=username)


# ════════════════════════════════════════════════
# ▶ LOGOUT
# ════════════════════════════════════════════════

@app.route("/logout", endpoint="logout")
@login_required
def logout():
    ''' Logout route for users '''
    logout_user()
    flash("Je bent nu uitgelogd.")
    return render_template("/public/login.html")



# ════════════════════════════════════════════════
# ▶ CONTACT FORM SUBMIT
# ════════════════════════════════════════════════

@app.route("/contact-form-submit", endpoint="contact-form-submit", methods=["POST"])
def contact_submit_form():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    message = request.form.get("message")

    subject, body = get_contact_mail_content(firstname, lastname, email, message)

    success, error = send_admin_email(subject, body, reply_to=email)
    if success:
        flash("We hebben jouw bericht goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "contact")
    else:
        flash(f"Er is een fout opgetreden!: {error}", "danger")

    return redirect(url_for("contact"))


# ════════════════════════════════════════════════
# ▶ MEMBERSHIP FORM SUBMIT
# ════════════════════════════════════════════════

@app.route("/membership-form-submit", endpoint="membership-form-submit", methods=["POST"])
def membership_submit_form():
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

    subject, body = get_membership_mail_content(
        firstname, lastname, email, phone, gsm, street, city, zip_code, membership_type, message
    )

    success, error = send_admin_email(subject, body, reply_to=email)
    if success:
        flash("We hebben je aanvraag goed ontvangen en bezorgen je zo snel mogelijk een antwoord.", "success")
        send_confirmation_email(email, f"{firstname} {lastname}", "membership")
    else:
        flash(f"Er is een fout opgetreden: {error}", "danger")

    return redirect(url_for("membership"))


# ════════════════════════════════════════════════
# ▶ ADMIN DASHBOARD PAGE
# ════════════════════════════════════════════════

@app.route("/dashboard", endpoint="dashboard")
def dashboard():
    ''' User dashboard '''
    return render_template("admin/dashboard.html")


# ════════════════════════════════════════════════
# ▶ ADMIN: ADD NEW USER
# ════════════════════════════════════════════════

@app.route("/nieuwe-gebruiker", methods=["GET", "POST"], endpoint="add_user")
def add_user():
    ''' Add new user to database. '''

    conn = get_db_connection()
    cur = conn.cursor()
    # Exclude 'super' from the roles list
    cur.execute("SELECT id, name FROM roles WHERE name != %s", ('super',))
    roles = cur.fetchall()

    try:
        if request.method == "POST":
            first_name = request.form.get("firstname", "").strip()
            last_name = request.form.get("lastname", "").strip()
            username = generate_username(first_name, last_name) # Use function to generate username based on first and last name
            token = str(random.randint(10000, 99999)) # Generate random 5-digit password
            email = request.form.get("email")
            is_active = True
            require_password_change = True
            # Fetch current user from session (if logged in), else set to None
            created_by = current_user.id if current_user.is_authenticated else None
            updated_by = current_user.id if current_user.is_authenticated else None
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)
            selected_role_id = request.form.get("role").lower()

            # Ensure username and password are not empty
            if not first_name or not last_name or not email:
                flash("Voornaam, achternaam en e-mail zijn vereist.")
                return render_template("admin/add_user.html", roles=roles)

            # Hash password before storing in database
            password_hash = generate_password_hash(token, method="pbkdf2:sha256")
            # Insert new user into users table and return id
            cur.execute(
                "INSERT INTO users (username, password_hash, email, is_active, first_name, last_name, require_password_change, created_by, updated_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (username, password_hash, email, is_active, first_name, last_name, require_password_change, created_by, updated_by, created_at, updated_at)
            )
            user_row = cur.fetchone()
            if not user_row or "id" not in user_row:
                raise Exception("Niet mogelijk om gebruiker te registeren of id op te halen.")
            user_id = user_row["id"]

            # Insert into user_role_map for each selected role
            cur.execute("SELECT id FROM roles WHERE id = %s", (selected_role_id,))
            role_row = cur.fetchone()
            if not role_row:
                raise Exception(f"Rol met id '{selected_role_id}' niet gevonden.")
            role_id = role_row["id"]
            cur.execute(
                "INSERT INTO user_role_map (user_id, role_id) VALUES (%s, %s)",
                (user_id, role_id)
            )
            conn.commit()
            send_login_credentials_email(email, first_name, username, token)
            flash(f"Registratie gelukt. Controleer e-mail met logingegevens. {username} {token}")
            return redirect("/dashboard")
        return render_template("admin/add_user.html", roles=roles)

    except Exception as e:
        conn.rollback()
        flash(f"Er is een fout opgetreden: {e}", "danger")
    finally:
        cur.close()




# ════════════════════════════════════════════════
# ▶ ADMIN: MANAGE NEWS POSTS
# ════════════════════════════════════════════════

# To be delete -> Centralized dashboard for all special users
@app.route('/author', endpoint="author")
@role_required('admin', 'author')
def author():
    ''' Admin page to manage website content '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM posts ORDER BY created_at DESC')
    posts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('author.html', posts=posts)


# ════════════════════════════════════════════════
# ▶ ADMIN: ADD NEWS POST
# ════════════════════════════════════════════════

# To be changed
@app.route('/redactie/nieuwsbericht-toevoegen', methods=['GET', 'POST'])
def add_post():
    ''' Add news post to database '''

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        date = request.form['date']

        image_file = request.files.get('image')
        filename = None

        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            else:
                flash('Alleen afbeeldingen zijn toegestaan (jpg, jpeg, png, gif)', 'danger')
                return redirect(request.url)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO posts (title, content, category, date, image_filename) VALUES (%s, %s, %s, %s, %s)',
                    (title, content, category, date, filename))
        conn.commit()
        cur.close()
        conn.close()

        flash('Bericht toegevoegd!', 'success')
        return redirect(url_for('author'))

    return render_template('add_post.html', form_title='Nieuw Bericht', post=None)


# ════════════════════════════════════════════════
# ▶ ADMIN: EDIT NEWS POST
# ════════════════════════════════════════════════

@app.route('/author/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    ''' Edit existing post in database '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cur.fetchone()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        date = request.form['date']

        image_file = request.files.get('image')
        filename = post['image_filename'] if post else None

        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                if post and post['image_filename']:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
            else:
                flash('Alleen afbeeldingen zijn toegestaan (jpg, jpeg, png, gif)', 'danger')
                return redirect(request.url)

        cur.execute('UPDATE posts SET title=%s, content=%s, category=%s, date=%s, image_filename=%s WHERE id=%s',
                    (title, content, category, date, filename, post_id))
        conn.commit()
        cur.close()
        conn.close()

        flash('Bericht bijgewerkt!', 'success')
        return redirect(url_for('author'))

    cur.close()
    conn.close()
    return render_template('add_edit_post.html', form_title='Bewerk Bericht', post=post)


# ════════════════════════════════════════════════
# ▶ ADMIN: DELETE NEWS POST
# ════════════════════════════════════════════════

@app.route('/author/delete/<int:post_id>')
@role_required('admin', 'author')
def delete_post(post_id):
    ''' Delete post from database '''
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cur.fetchone()

    if post and post['image_filename']:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename'])
        if os.path.exists(image_path):
            os.remove(image_path)

    cur.execute('DELETE FROM posts WHERE id = %s', (post_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash('Bericht en afbeelding verwijderd!', 'info')
    return redirect(url_for('author'))




# ════════════════════════════════════════════════
# ▶ FUNCTIONS
# ════════════════════════════════════════════════

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png', 'gif'}


def get_existing_usernames():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users")
    usernames = {row["username"] for row in cur.fetchall()}
    cur.close()
    conn.close()
    return usernames


def generate_username(first_name, last_name):
    '''
    Generate username based on first and last name.
    Append number if user already exists.
    '''
    existing_usernames = get_existing_usernames()

    # Remove spaces and special characters from last name
    clean_last = re.sub(r'[^a-zA-Z0-9]', '', last_name.lower())
    base = (first_name[0] + clean_last).lower()
    username = base
    counter = 2
    while username in existing_usernames:
        username = f"{base}{counter}"
        counter += 1
    return username


# ════════════════════════════════════════════════
# ▶ MAIN ENTRY POINT
# ════════════════════════════════════════════════©

if __name__ == '__main__':

    # For production deploy only
    # app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))

    # For development deploy only
    app.run(debug=True)


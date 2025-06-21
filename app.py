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
app.secret_key = os.environ.get("SECRET_KEY")
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
            if 'cur' in locals() and cur:
                cur.close()
            if 'conn' in locals() and conn:
                conn.close()
            conn.close()
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
    try:
        cur.execute("""
        SELECT id, title, content, created_at
        FROM posts
        WHERE is_pinned = %s and is_published = %s and is_deleted = %s and visibility = %s
        ORDER BY created_at DESC
        LIMIT 4""", (True, True, False, "public"))
        posts = cur.fetchall()

        for post in posts:
            post_id = post["id"]
            cur.execute("""
                SELECT t.name
                FROM tag_map tm
                LEFT JOIN tags t ON tm.tag_id = t.id
                WHERE tm.entity_type = %s AND tm.entity_id = %s
                ORDER BY t.name ASC
            """, ("post", post_id))
            post_tags = [row["name"] for row in cur.fetchall()]
            post["tags"] = post_tags  # Attach tags to the post

        for post in posts:
            post_id = post["id"]
            cur.execute("""
                SELECT url
                FROM post_images
                WHERE post_id = %s AND is_main = %s
            """, (post_id, True))
            image_row = cur.fetchone()
            image_url = image_row["url"] if image_row else None
            post["image_url"] = image_url

    finally:
        return render_template("public/index.html", posts=posts)


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
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT title, subtitle, event_date, location
            FROM events
            WHERE is_published = %s 
              AND is_deleted = %s 
              AND visibility = %s 
              AND event_date >= CURRENT_DATE
            ORDER BY event_date ASC
            LIMIT 10""", (True, False, "public"))
        events = cur.fetchall()
    finally:
        cur.close()
        conn.close()
    return render_template("public/agenda.html", events=events)


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
        elif not check_password_hash(user["password_hash"], password):
            flash("Ongeldige logingegevens.", "danger")
            return redirect(url_for("login"))
        elif not user["is_active"]:
            flash("Gebruiker is niet actief.", "danger")
            return redirect(url_for("login"))

        user_obj = User.get(user["id"])
        if user_obj is None:
            flash("Gebruiker niet gevonden.", "warning")
            return redirect(url_for("login"))

        if user["require_password_change"]:
            login_user(user_obj)
            return redirect(url_for("set_password"))

        login_user(user_obj)
        return redirect(url_for("dashboard"))

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
        if 'cur' in locals() and cur:
            cur.close()
        if 'conn' in locals() and conn:
            conn.close()


# ════════════════════════════════════════════════
# ▶ ADMIN: ADD NEW ROLE
# ════════════════════════════════════════════════

@app.route("/nieuwe-rol", methods=["GET", "POST"], endpoint="add_role")
def add_role():
    ''' Add new role to database. '''

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM permissions")
    all_permissions = cur.fetchall()


    try:
        if request.method == "POST":
            name = request.form.get("name", "")
            name = re.sub(r'\s+', '_', name.strip().lower())
            description = request.form.get("description", "")
            selected_permissions = request.form.getlist("permissions")

            # Fetch current user from session (if logged in), else set to None
            created_by = current_user.id if current_user.is_authenticated else None
            updated_by = current_user.id if current_user.is_authenticated else None
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)

            cur.execute(
                "INSERT INTO roles (name, description, created_by, updated_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (name, description, created_by, updated_by, created_at, updated_at)
            )

            role_row = cur.fetchone()
            if not role_row or "id" not in role_row:
                raise Exception("Niet mogelijk om rol toe te voegen of id op te halen.")
            role_id = role_row["id"]
            conn.commit()
            flash('Rol toegevoegd aan database.', 'success')


            for permission_id in selected_permissions:
                try:
                    cur.execute("INSERT INTO role_permission_map (role_id, permission_id) VALUES (%s, %s)", (role_id, permission_id))
                except Exception as insert_exc:
                    conn.rollback()
                    flash(f"Fout bij koppelen van recht aan rol (role_id={role_id}): {insert_exc}", "danger")
                    return redirect(url_for("add_permission"))


            conn.commit()
            flash('Recht gekoppeld aan rol(len).', 'success')

            return redirect(url_for("dashboard"))
        return render_template("admin/add_role.html", permissions=all_permissions)

    except Exception as e:
        conn.rollback()
        flash(f"Er is een fout opgetreden: {e}", "danger")
    finally:
        cur.close()


# ════════════════════════════════════════════════
# ▶ ADMIN: ADD NEW PERMISSION
# ════════════════════════════════════════════════

@app.route("/nieuw-recht", methods=["GET", "POST"], endpoint="add_permission")
def add_permission():
    ''' Add new permission to database. '''

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM roles")
    all_roles = cur.fetchall()

    try:
        if request.method == "POST":
            name = request.form.get("name", "")
            name = re.sub(r'\s+', '_', name.strip().lower())
            description = request.form.get("description", "")
            selected_roles = request.form.getlist("roles")

            # Fetch current user from session (if logged in), else set to None
            created_by = current_user.id if current_user.is_authenticated else None
            updated_by = current_user.id if current_user.is_authenticated else None
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)

            # Insert new permission and return its id
            cur.execute(
                "INSERT INTO permissions (name, description, created_by, updated_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (name, description, created_by, updated_by, created_at, updated_at)
            )
            permission_row = cur.fetchone()
            if not permission_row or "id" not in permission_row:
                raise Exception("Niet mogelijk om recht toe te voegen of id op te halen.")
            permission_id = permission_row["id"]

            conn.commit()
            flash('Recht toegevoegd aan database.', 'success')

            for role_id in selected_roles:
                try:
                    cur.execute("INSERT INTO role_permission_map (role_id, permission_id) VALUES (%s, %s)", (role_id, permission_id))
                except Exception as insert_exc:
                    conn.rollback()
                    flash(f"Fout bij koppelen van recht aan rol (role_id={role_id}): {insert_exc}", "danger")
                    return redirect(url_for("add_permission"))


            conn.commit()
            flash('Recht gekoppeld aan rol(len).', 'success')
        
            return redirect(url_for("dashboard"))
        return render_template("admin/add_permission.html", roles=all_roles)

    except Exception as e:
        conn.rollback()
        flash(f"Er is een fout opgetreden: {e}", "danger")
    finally:
        cur.close()


# ════════════════════════════════════════════════
# ▶ ADMIN: MANAGE NEWS POSTS
# ════════════════════════════════════════════════

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
# ▶ ADMIN: ADD NEW POST
# ════════════════════════════════════════════════

@app.route("/nieuwe-post", methods=["GET", "POST"], endpoint="add_post")
def add_post():
    ''' Add new news post to database '''

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM tags")
    all_tags = cur.fetchall()

    try:
        if request.method == "POST":
            title = request.form.get("title")
            content = request.form.get("content")
            is_published = False # Default
            visibility = "public" # Default
            is_deleted = False # Default
            is_pinned = False # Default
            selected_tags = request.form.getlist("tags")

            # Fetch current user from session (if logged in), else set to None
            created_by = current_user.id if current_user.is_authenticated else None
            updated_by = current_user.id if current_user.is_authenticated else None
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)

            # Insert new post and return its id
            cur.execute(
                "INSERT INTO posts (title, content, is_published, visibility, is_deleted, is_pinned, created_by, updated_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (title, content, is_published, visibility, is_deleted, is_pinned, created_by, updated_by, created_at, updated_at)
            )
            post_row = cur.fetchone()
            if not post_row or "id" not in post_row:
                raise Exception("Niet mogelijk om post toe te voegen of id op te halen.")
            post_id = post_row["id"]

            conn.commit()
            flash('Post toegevoegd aan database.', 'success')

            for tag_id in selected_tags:
                try:
                    cur.execute("INSERT INTO tag_map (entity_type, entity_id, tag_id) VALUES (%s, %s, %s)", ("post", post_id, tag_id))
                except Exception:
                    conn.rollback()
                    flash(f"Fout bij koppelen van post aan tag.", "danger")
                    return redirect(url_for("add_post"))
            conn.commit()
        
            return redirect(url_for("dashboard"))
        return render_template("admin/add_post.html", tags=all_tags)

    except Exception as e:
        conn.rollback()
        flash(f"Er is een fout opgetreden: {e}", "danger")
        return render_template("admin/add_post.html", tags=all_tags)
    finally:
        cur.close()


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
# ▶ ADMIN: ADD NEW EVENT
# ════════════════════════════════════════════════
# Action types, recurrences and exceptions not set up yet
@app.route("/nieuw-evenement", methods=["GET", "POST"], endpoint="add_event")
def add_event():
    ''' Add new news event to database '''

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM tags") # Fetch all tags
    all_tags = cur.fetchall()
    cur.execute("SELECT id, name FROM event_action_types") # Fetch all action types
    all_event_action_types = cur.fetchall()

    try:
        if request.method == "POST":
            title = request.form.get("title")
            subtitle = request.form.get("subtitle")
            description = request.form.get("description")
            event_date_str = request.form.get("event_date")
            location = request.form.get("location")
            is_published = False # Default
            visibility = "public" # Default
            is_deleted = False # Default
            action_type = request.form.get("action_type")
            selected_tags = request.form.getlist("tags")

            event_date = datetime.strptime(event_date_str, "%Y-%m-%dT%H:%M")


            # Fetch current user from session (if logged in), else set to None
            created_by = current_user.id if current_user.is_authenticated else None
            updated_by = current_user.id if current_user.is_authenticated else None
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)

            # Insert new event and return its id
            cur.execute(
                "INSERT INTO events (title, subtitle, description, event_date, location, is_published, visibility, is_deleted, created_by, updated_by, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (title, subtitle, description, event_date, location, is_published, visibility, is_deleted, created_by, updated_by, created_at, updated_at)
            )
            event_row = cur.fetchone()
            if not event_row or "id" not in event_row:
                raise Exception("Niet mogelijk om evenement toe te voegen of id op te halen.")
            event_id = event_row["id"]

            conn.commit()
            flash('Evenement toegevoegd aan database.', 'success')

            for tag_id in selected_tags:
                try:
                    cur.execute("INSERT INTO tag_map (entity_type, entity_id, tag_id) VALUES (%s, %s, %s)", ("event", event_id, tag_id))
                except Exception:
                    conn.rollback()
                    flash(f"Fout bij koppelen van evenement aan tag.", "danger")
                    return redirect(url_for("add_event"))
            conn.commit()
        
            return redirect(url_for("dashboard"))
        return render_template("admin/add_event.html", tags=all_tags)

    except Exception as e:
        conn.rollback()
        flash(f"Er is een fout opgetreden: {e}", "danger")
        return render_template("admin/add_event.html", tags=all_tags)
    finally:
        cur.close()


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


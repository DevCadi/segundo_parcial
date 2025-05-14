from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- Conexión e inicialización de base de datos ---
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

# --- Clase User para Flask-Login ---
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# --- Rutas de la aplicación ---
@app.route("/")
def index():
    conn = get_db_connection()
    posts = conn.execute("""
        SELECT posts.id, posts.title, posts.content, posts.created_at, users.username AS author
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """).fetchall()
    conn.close()
    return render_template("index.html", posts=posts)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_pass = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed_pass),
            )
            conn.commit()
            flash('Usuario registrado exitosamente. Inicia sesión.', 'success')
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash('El nombre de usuario ya está registrado.', 'danger')
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password_hash"]
        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for("dashboard"))
        else:
            flash('Credenciales inválidas.', 'danger')
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    posts = conn.execute("""
        SELECT posts.*, users.username AS author
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        posts=posts,
        username=current_user.username,
        user_id=current_user.id,
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for("login"))

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        if not title or not content:
            flash("Título y contenido requeridos", "danger")
        else:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                (title, content, current_user.id)
            )
            conn.commit()
            conn.close()
            flash("Post creado exitosamente", "success")
            return redirect(url_for("dashboard"))
    return render_template("create.html")

@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit(post_id):
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    if post["user_id"] != current_user.id:
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        if not title or not content:
            flash("Título y contenido requeridos", "danger")
        else:
            conn.execute(
                "UPDATE posts SET title = ?, content = ? WHERE id = ?",
                (title, content, post_id)
            )
            conn.commit()
            conn.close()
            flash("Post actualizado exitosamente", "success")
            return redirect(url_for("dashboard"))

    return render_template("edit.html", post=post)

@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete(post_id):
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    if post["user_id"] != current_user.id:
        abort(403)
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash("Post eliminado exitosamente", "info")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

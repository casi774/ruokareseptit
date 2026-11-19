import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

DATABASE = Path(app.root_path) / 'database.db'
PBKDF2_ITERATIONS = 200_000

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    connection = get_db_connection()
    connection.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        );
    ''')
    connection.execute(
        'CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username)'
    )
    connection.commit()
    connection.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('ascii'), PBKDF2_ITERATIONS
    )
    return f'{salt}${digest.hex()}'

def verify_password(password, stored_password):
    if '$' not in stored_password:
        return hmac.compare_digest(password, stored_password)

    salt, expected_hex = stored_password.split('$', 1)
    actual = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('ascii'), PBKDF2_ITERATIONS
    )
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Enter a username and password.')
            return render_template("register.html")

        connection = get_db_connection()
        try:
            connection.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                [username, hash_password(password)]
            )
            connection.commit()
        except sqlite3.IntegrityError:
            flash('That username is already in use.')
            return render_template("register.html")
        finally:
            connection.close()
        flash('Registration successful. You can now log in.')
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Enter a username and password.')
            return render_template("login.html")

        connection = get_db_connection()
        user = connection.execute(
            '''SELECT id, username, password
            FROM users
            WHERE username = ?''',
            [username]
        ).fetchone()

        if user and verify_password(password, user['password']):
            if '$' not in user['password']:
                connection.execute(
                    'UPDATE users SET password = ? WHERE id = ?',
                    [hash_password(password), user['id']]
                )
                connection.commit()
            connection.close()
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))

        connection.close()
        flash('Invalid username or password.')
    return render_template("login.html")

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/new_recipe')
def new_recipe():
    return render_template("new_recipe.html")

@app.route('/recipes')
def recipes():
    return render_template("recipes.html")
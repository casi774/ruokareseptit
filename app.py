import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for

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
        CREATE TABLE IF NOT EXISTS recipes (
            recipe_id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            instructions TEXT,
            category TEXT,
            diets TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    connection.execute(
        'CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username)'
    )
    recipe_columns = {
        row['name'] for row in connection.execute('PRAGMA table_info(recipes)')
    }
    for column, column_type in (
        ('instructions', 'TEXT'),
        ('category', 'TEXT'),
        ('diets', 'TEXT'),
        ('user_id', 'INTEGER'),
    ):
        if column not in recipe_columns:
            connection.execute(
                f'ALTER TABLE recipes ADD COLUMN {column} {column_type}'
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

@app.route('/new_recipe', methods=['GET', 'POST'])
def new_recipe():
    if 'user_id' not in session:
        flash('Kirjaudu sisaan jotta voit lisätä reseptin.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        instructions = request.form.get('instructions', '').strip()
        category = request.form.get('food_type', '').strip()
        diets = ','.join(request.form.getlist('diet'))

        if not title or not category:
            flash('Anna reseptille nimi ja valitse ruokalaji.')
            return render_template("new_recipe.html")

        connection = get_db_connection()
        connection.execute(
            '''INSERT INTO recipes
               (title, description, instructions, category, diets, user_id)
               VALUES (?, ?, ?, ?, ?, ?)''',
            [title, description, instructions, category, diets, session['user_id']]
        )
        connection.commit()
        connection.close()
        flash('Resepti lisattiin.')
        return redirect(url_for('recipes'))

    return render_template("new_recipe.html")

@app.route('/recipes')
def recipes():
    connection = get_db_connection()
    recipes = connection.execute(
        '''SELECT r.recipe_id, r.title, r.description, r.instructions, r.user_id,
                  r.category, r.diets, u.username
           FROM recipes r
           JOIN users u ON u.id = r.user_id
           ORDER BY r.recipe_id DESC'''
    ).fetchall()
    connection.close()
    return render_template(
        "recipes.html", recipes=recipes, current_user_id=session.get('user_id')
    )

@app.route('/recipes/<int:recipe_id>/edit', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    if 'user_id' not in session:
        flash('Kirjaudu sisään muokataksesi reseptiä.')
        return redirect(url_for('login'))

    connection = get_db_connection()
    recipe = connection.execute(
        '''SELECT recipe_id, title, description, instructions, category, diets
           FROM recipes
           WHERE recipe_id = ? AND user_id = ?''',
        [recipe_id, session['user_id']]
    ).fetchone()
    if recipe is None:
        connection.close()
        abort(404)

    if request.method == 'POST':
        title = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        instructions = request.form.get('instructions', '').strip()
        category = request.form.get('food_type', '').strip()
        diets = ','.join(request.form.getlist('diet'))

        if not title or not category:
            connection.close()
            flash('Anna reseptille nimi ja valitse ruokalaji.')
            return render_template('edit_recipe.html', recipe=recipe)

        connection.execute(
            '''UPDATE recipes
               SET title = ?, description = ?, instructions = ?, category = ?, diets = ?
               WHERE recipe_id = ? AND user_id = ?''',
            [
                title, description, instructions, category, diets,
                recipe_id, session['user_id']
            ]
        )
        connection.commit()
        connection.close()
        flash('Resepti päivitettiin.')
        return redirect(url_for('recipes'))

    connection.close()
    return render_template('edit_recipe.html', recipe=recipe)

@app.route('/recipes/<int:recipe_id>/delete', methods=['POST'])
def delete_recipe(recipe_id):
    if 'user_id' not in session:
        flash('Kirjaudu sisään poistaaksesi reseptin.')
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.execute(
        'DELETE FROM recipes WHERE recipe_id = ? AND user_id = ?',
        [recipe_id, session['user_id']]
    )
    connection.commit()
    connection.close()
    if cursor.rowcount == 0:
        abort(404)
    flash('Resepti poistettiin.')
    return redirect(url_for('recipes'))
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/new_recipe')
def new_recipe():
    return render_template("new_recipe.html")

@app.route('/recipes')
def recipes():
    return render_template("recipes.html")
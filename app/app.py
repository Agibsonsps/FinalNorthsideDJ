from flask import Flask, render_template, request, redirect, url_for, flash, session  # for Flask
import bcrypt
import sqlite3
import requests

app = Flask(__name__)
app.secret_key = 's3cr3t'


def init_db():
    with app.app_context():
        db = sqlite3.connect('users.db')
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)''')
        db.commit()


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)


@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #hashed_password = generate_password_hash(password, method='sha256')
        hashed_password = hash_password(password)
        try:
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                db.commit()
            flash('Registered successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            #if user and check_password_hash(user[1], password):
            if user and check_password(user[1], password):
                session['user'] = user[0]
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password!', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/search', methods=['GET', 'POST'])
def search():
    print("Searching...")
    #if 'user' not in session:
    #    return redirect(url_for('login'))
    if request.method == 'POST':
        artist_name = request.form['artist']
        print(artist_name)
        albums = search_albums(artist_name)
        return render_template('results.html', artist=artist_name, albums=albums)
    return render_template('search.html')


def search_albums(artist_name):
    API_KEY = '523532'
    URL = f'https://theaudiodb.com/api/v1/json/{API_KEY}/searchalbum.php?s={artist_name}'
    print(URL)
    response = requests.get(URL)
    print(response)
    data = response.json()
    print(data)
    albums = data['album']
    return albums


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

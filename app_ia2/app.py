import openpyxl
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import requests
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.secret_key = 's3cr3t'


def hash_password(password):
    # Hash the password using bcrypt for secure storage
    return generate_password_hash(password, method='pbkdf2:sha256')


gamesdoc = pd.read_excel('/Users/asgibsonpc2022/PycharmProjects/FinalNorthsideDJ/app_ia2/GameData.xlsx')


@app.route('/')
def index():
    # Display a list of events and their associated data
    # Prevent SQL injection by not directly inserting user input into SQL queries
    events = None
    with sqlite3.connect('Esportsapp.db') as db:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM events''')
        events = cursor.fetchall()
        votedata = {}
        #for v in votedata:
            # Prevent SQL injection by not directly inserting user input into SQL queries
            #cursor.execute('''SELECT * FROM songs''' + str(v[0]))
            #votedata[v[0]] = cursor.fetchall()
            #print(votedata)
        #cursor.execute('''SELECT * FROM songs''' + str(1))
        #songsdata = cursor.fetchall()
        cursor.close()
        #songsdata.sort(key=sort_songs, reverse=True)
    return render_template('index.html', events=events)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['firstname']
        user_type = request.form['user_type']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        print(hashed_password)
        try:
            with sqlite3.connect('Esportsapp.db') as db:
                cursor = db.cursor()
                # Insert user data into the 'users' table, using parameters to prevent SQL injection
                cursor.execute('INSERT INTO users (firstname, lastname, user_type, email, username, hashed_password) VALUES (?, ?, ?, ?, ?, ?)', (firstname, lastname, user_type, email, username, hashed_password))
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
        with sqlite3.connect('Esportsapp.db') as db:
            cursor = db.cursor()
            # Select user data using a parameter to prevent SQL injection
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            cursor.close()
            #CHECK HERE! User call is messed up.
            print(type(password))
            print(password)
            print(user[6])
            if user and check_password_hash(user[6], password):
                session['user'] = user[0]
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password!', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
def search():
    if "user" not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        game_name = request.form['game']
        gameresults = search_games(game_name)
        return render_template('results.html', game_name=game_name, gameresults=gameresults)
    return render_template('search.html')


@app.route('/results', methods=['GET', 'POST'])
def results():
    # Display details about a selected song and allow users to add it to a playlist
    if "user" not in session:
        return redirect(url_for('login'))
    return render_template('results.html')


def search_games(game):
    query = game.lower()
    wb = openpyxl.load_workbook('/Users/asgibsonpc2022/PycharmProjects/FinalNorthsideDJ/app_ia2/GameData.xlsx')
    ws = wb["Data_Used_For_Reviews"]
    games_dict = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row[25]:
            continue
        game_title = row[2]
        game_details = {
            "trailer_link": row[25],
            "id": row[1],
        }
        if query in game_title.lower():
            games_dict[game_title] = game_details
    print(request.form['game'])
    return games_dict


@app.route('/event', methods=['GET', 'POST'])
# this get all event info and returns to event.html
def event():
    # this returns all events with all songs voted for. (not per event)
    events = None
    if "user" not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('Esportsapp.db') as db:
        cursor = db.cursor()
        return render_template('event.html')


@app.route('/profile', methods={'GET', 'POST'})
def profile():
    return render_template('profile.html')


@app.route('/create_event', methods=['GET', 'POST'])
# this creates a new event and returns to event.html
def create_event():
    if "user" not in session:
        return redirect(url_for('login'))
    print("started function create_event")
    if request.method == 'POST':
        print("started if request.method == 'POST'")
        event_name = request.form['event_name']
        time = request.form['time']
        location = request.form['location']
        description = request.form['description']
        user = session.get('user')
        if user in session:
            return redirect(url_for('login'))
        try:
            with sqlite3.connect('Esportsapp.db') as db:
                cursor = db.cursor()
                print("started with sqlite3.connect('Esportsapp.db') as db:")
                cursor.execute('''INSERT INTO events (name, time, location, description) VALUES (?, ?, ?, ?)''', (event_name, time, location, description))
                db.commit()
                # cursor.execute('''CREATE TABLE IF NOT EXISTS event_id_attendees (attendee_ID TEXT, event_ID TEXT)''')
                # cursor.execute('''CREATE TABLE IF NOT EXISTS event_id_songs (song_ID TEXT, event_ID TEXT)''')
                # playlist name = event name + playlist
                playlist_name = event_name + ' _playlist'
                cursor.execute("SELECT * FROM events WHERE name = ?", (event_name,))
                event_ID = cursor.fetchone()[0]
                # make playlist table
                # make song table
                cursor.execute('''CREATE TABLE IF NOT EXISTS songs'''+str(event_ID)+''' (song_ID INTEGER PRIMARY KEY, name TEXT, artist TEXT, album TEXT, votes INTEGER)''')
                # make attendee table
                cursor.execute('''CREATE TABLE IF NOT EXISTS attendees (event_ID INTEGER PRIMARY KEY, name TEXT, email TEXT, username TEXT, hashed_password TEXT)''')
                db.commit()
            return render_template('event.html', event_name=event_name, time=time, location=location, description=description)
        except sqlite3.IntegrityError:
            flash('Event already exists!', 'danger')
        db.close()
    return render_template('create_event.html')


@app.route('/event_data')
def event_data():
    if "user" not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('Esportsapp.db') as db:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM events''')
        events = cursor.fetchall()
    return render_template('event_data.html', events=events)


if __name__ == '__main__':
    app.run(debug=True, port=4002)

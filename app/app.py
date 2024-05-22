from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
import sqlite3
import requests
import pandas as pd

app = Flask(__name__)
app.secret_key = 's3cr3t'


def hash_password(password):
    # Hash the password using bcrypt for secure storage
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(hashed_password, user_password):
    # Check if a provided password matches the hashed password in the database
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)


gamesdoc = pd.read_excel('/Users/asgibsonpc2022/PycharmProjects/FinalNorthsideDJ/app_ia2/GameData.xlsx')
print(gamesdoc.head())

@app.route('/')
def index():
    # Display a list of events and their associated data
    # Prevent SQL injection by not directly inserting user input into SQL queries
    events = None
    with sqlite3.connect('NSDJ.db') as db:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM events''')
        events = cursor.fetchall()
        votedata = {}
        for v in votedata:
            # Prevent SQL injection by not directly inserting user input into SQL queries
            cursor.execute('''SELECT * FROM songs''' + str(v[0]))
            votedata[v[0]] = cursor.fetchall()
            print(votedata)
        cursor.execute('''SELECT * FROM songs''' + str(1))
        songsdata = cursor.fetchall()
        cursor.close()
        songsdata.sort(key=sort_songs, reverse=True)
    return render_template('index.html', songsdata=songsdata, votedata=votedata, events=events)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        try:
            with sqlite3.connect('NSDJ.db') as db:
                cursor = db.cursor()
                # Insert user data into the 'users' table, using parameters to prevent SQL injection
                cursor.execute('INSERT INTO users (name, email, username, hashed_password) VALUES (?, ?, ?, ?)', (name, email, username, hashed_password))
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
        with sqlite3.connect('NSDJ.db') as db:
            cursor = db.cursor()
            # Select user data using a parameter to prevent SQL injection
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            cursor.close()
            if user and check_password(user[4], password):
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
# this gets the artist name and returns albyms to results.html
    if "user" not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        artist_name = request.form['artist']
        albums = search_albums(artist_name)
        return render_template('results.html', artist=artist_name, albums=albums)
    return render_template('search.html')


@app.route('/results/<albumID>', methods=['GET', 'POST'])
def results(albumID):
    if "user" not in session:
        return redirect(url_for('login'))
    print("Album ID: ", albumID)
    songs = search_songs(albumID)
    strAlbum = songs[0]['strAlbum']
    return render_template('results_albumid.html', songs=songs, strAlbum=strAlbum, albumID=albumID)


@app.route('/results/<albumID>/<songID>', methods=['GET', 'POST'])
def results_songs(albumID, songID):
    # Display details about a selected song and allow users to add it to a playlist
    if "user" not in session:
        return redirect(url_for('login'))
    print("Album ID-Songs: ", albumID)
    print("Song ID: ", songID)
    print(request.method)
    songinfo = song_info(songID)
    print(songinfo)
    if request.method == 'POST':
        with sqlite3.connect('NSDJ.db') as db:
            cursor = db.cursor()
            cursor.execute('''SELECT * FROM songs'''+str(1)+''' WHERE song_ID = ?''', (int(songID),))
            eventsong = cursor.fetchone()
            votes = 0
            if eventsong:
                votes = eventsong[4]
            votes += 1
            cursor.execute('''INSERT OR REPLACE INTO songs'''+str(1)+''' (song_ID, name, artist, album, votes) VALUES (?, ?, ?, ?, ?)''', (int(songID), songinfo['strTrack'], songinfo['strArtist'], songinfo['strAlbum'], votes))
            db.commit()
            cursor.close()
        flash('Song added to playlist!', 'success')
        return redirect(url_for('search'))
    return render_template('results_songid.html', albumID=albumID, songID=songID, songinfo=songinfo)


def search_albums(artist_name):
    # Search for albums by an artist using an external API
    api_key = '523532'
    url = f'https://theaudiodb.com/api/v1/json/{api_key}/searchalbum.php?s={artist_name}'
    response = requests.get(url)
    data = response.json()
    albums = data['album']
    albumID = albums[0]['idAlbum']
    return albums


def search_songs(albumID):
    # Search for songs by album ID using an external API
    api_key = '523532'
    url = f'https://theaudiodb.com/api/v1/json/{api_key}/track.php?m={albumID}'
    response = requests.get(url)
    data = response.json()
    songs = data['track']
    print("Song info:", songs)
    return songs


def song_info(songID):
    # Get information about a song by song ID using an external API
    api_key = '523532'
    url = f'https://theaudiodb.com/api/v1/json/{api_key}/track.php?h={songID}'
    response = requests.get(url)
    data = response.json()
    song = data['track']
    print("Song info:", song)
    return song[0]


@app.route('/event', methods=['GET', 'POST'])
# this get all event info and returns to tournament.html
def event():
    # this returns all events with all songs voted for. (not per event)
    events = None
    if "user" not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('NSDJ.db') as db:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM events''')
        events = cursor.fetchall()
        votedata = {}
        for v in votedata:
            cursor.execute('''SELECT * FROM songs''' + str(v[0]))
            votedata[v[0]] = cursor.fetchall()
        print(votedata)
        cursor.execute('''SELECT * FROM songs''' + str(1))
        songsdata = cursor.fetchall()
        print(songsdata)
        cursor.close()
        songsdata.sort(key=sort_songs, reverse=True)
        return render_template('tournament.html', events=events, votedata=votedata, songsdata=songsdata)


def sort_songs(data):
    return data[4]


@app.route('/create_event', methods=['GET', 'POST'])
# this creates a new event and returns to tournament.html
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
            with sqlite3.connect('NSDJ.db') as db:
                cursor = db.cursor()
                print("started with sqlite3.connect('NSDJ.db') as db:")
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
            return render_template('tournament.html', event_name=event_name, time=time, location=location, description=description)
        except sqlite3.IntegrityError:
            flash('Event already exists!', 'danger')
        db.close()
    return render_template('create_tournament.html')


@app.route('/event_data')
def event_data():
    if "user" not in session:
        return redirect(url_for('login'))
    with sqlite3.connect('NSDJ.db') as db:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM events''')
        events = cursor.fetchall()
    return render_template('event_data.html', events=events)


if __name__ == '__main__':
    app.run(debug=True)

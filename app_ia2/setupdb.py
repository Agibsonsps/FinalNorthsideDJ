import sqlite3

conn = sqlite3.connect('Esportsapp.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users 
    (   
        user_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        firstname TEXT, 
        lastname TEXT,
        user_type TEXT,
        email TEXT,
        username TEXT UNIQUE, 
        hashed_password TEXT
    )
''')

#KEEPING ONLY TO KEEP APP RUNNING
cursor.execute('''
    CREATE TABLE IF NOT EXISTS events 
    (
        event_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        name TEXT, 
        time TEXT, 
        location TEXT, 
        description TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS friends 
    (
        friending_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_ID1 TEXT, 
        user_ID2 TEXT, 
        verify BOOLEAN
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS tournament 
    (
        tournament_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        type TEXT, 
        start TEXT, 
        status TEXT,
        description TEXT,
        end TEXT,
        game_ID,
        platform,
        game_tn_url TEXT
    )
''')
#USE WHEN MAKING TOURNAMENTS IN APP.PY
#cursor.execute('''
 #   CREATE TABLE IF NOT EXISTS (tournament_ID)match(1)
  #  (
   #     match_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    #    tournament_ID,
     #   datetime TEXT,
      #  team_ID(1)
       # team_ID(2)
    #)
#''')


cursor.execute('''
    CREATE TABLE IF NOT EXISTS teams 
    (
        team_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        leader_ID INTEGER, 
        team_name TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS team_members 
    (
        team_ID INTEGER PRIMARY KEY, 
        user_ID INTEGER
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS fave_games 
    (
        fave_game_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        user_ID INTEGER,
        game_ID INTEGER
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS fave_genre 
    (
        fave_genre_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        user_ID INTEGER,
        genre_ID INTEGER
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS genres
    (
        genre_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        name INTEGER
    )
''')
cursor.execute('''
INSERT INTO genres (name) VALUES (?)
''', ("action",))


conn.commit()
conn.close()

print("Database and tables created successfully!")
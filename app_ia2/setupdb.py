import sqlite3

conn = sqlite3.connect('NSDJ.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users 
    (   
        user_ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        name TEXT, 
        email TEXT, 
        username TEXT UNIQUE, 
        hashed_password TEXT
    )
''')

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
    CREATE TABLE IF NOT EXISTS attendees
    (
        user_ID INTEGER,
        event_ID INTEGER
    )
''')

conn.commit()
conn.close()

print("Database and tables created successfully!")
# This script creates an SQLite database to manage the news posts
# Only execute once to create the database

import sqlite3

# Connect to (or create) the database
conn = sqlite3.connect('database/posts.db')

# Create the posts table
conn.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL,
        image_filename TEXT
    )
''')

conn.commit()
conn.close()

print("Database initialized with 'posts' table.")

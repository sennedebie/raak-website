# Run once to initialize the database for authentication
# Or run it again to reset the database

from database import get_db_connection

def create_users_table():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("✅ Users table created successfully.")

if __name__ == "__main__":
    create_users_table()
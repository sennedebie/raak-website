# ════════════════════════════════════════════════
# ▶ IMPORTS
# ════════════════════════════════════════════════

import os
import psycopg2
from dotenv import load_dotenv


# ════════════════════════════════════════════════
# ▶ LOAD .env VARIABLES
# ════════════════════════════════════════════════

# Loads variables from .env into environment
load_dotenv()  


# ════════════════════════════════════════════════
# ▶ CHECK DB CONNECTION
# ════════════════════════════════════════════════

DATABASE_URL = os.getenv("DATABASE_URL")

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT 1;")
    print("Database connection successful!")
    print("Database URL:", DATABASE_URL)
    cur.close()
    conn.close()
except Exception as e:
    print("Database connection failed:")
    print(e)


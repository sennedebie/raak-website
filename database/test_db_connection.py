# ════════════════════════════════════════════════
# ▶ IMPORTS
# ════════════════════════════════════════════════

import os
import psycopg2


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

    
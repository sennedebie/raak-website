# ════════════════════════════════════════════════
# ▶ IMPORTS & LOADS
# ════════════════════════════════════════════════

import os
import psycopg2
import psycopg2.extras


# ════════════════════════════════════════════════
# ▶ CONNECT TO POSTGRESQL DATABASE
# ════════════════════════════════════════════════

def get_db_connection():
    conn = psycopg2.connect(
        os.environ["DATABASE_URL"],  # Will use Railway's environment variable
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    return conn
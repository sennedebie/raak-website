# ════════════════════════════════════════════════
# ▶ IMPORTS & LOADS
# ════════════════════════════════════════════════

import os
import psycopg2
import psycopg2.extras


# ════════════════════════════════════════════════
# ▶ CONNECT TO POSTGRESQL DATABASE
# ════════════════════════════════════════════════

def get_db_connection(user_id=None):
    conn = psycopg2.connect(
        os.environ["DATABASE_URL"],  # Will use Railway's environment variable
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    if user_id is not None:
        with conn.cursor() as cur:
            cur.execute("SET session \"app.current_user_id\" = %s;", (str(user_id),))
    return conn
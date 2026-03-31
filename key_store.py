from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "data" / "xljworkflowcipher.sqlite3"
CONFIG_PATH = Path(__file__).resolve().parent / "service.env"
SESSION_COOKIE_NAME = "xljworkflowcipher_session"
SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
PASSWORD_ITERATIONS = 200000
REMOTE_TIMEOUT_SECONDS = 15
EXPIRY_MODES = {
    "day": timedelta(days=1),
    "week": timedelta(days=7),
    "month": timedelta(days=30),
    "unlimited": None,
}


class KeyStoreError(ValueError):
    pass


def _normalized_external_url(value: str | None) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return value.rstrip("/")


def _plugin_config_value(name: str) -> str:
    env_value = os.getenv(name)
    if env_value is not None:
        return env_value.strip()

    if not CONFIG_PATH.is_file():
        return ""

    try:
        for raw_line in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() != name:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            return value.strip()
    except OSError:
        return ""

    return ""


def _remote_api_base() -> str:
    return _normalized_external_url(_plugin_config_value("XLJWORKFLOWCIPHER_API_BASE"))


def _remote_request_json(path: str, payload: dict | None = None) -> dict | None:
    remote_api_base = _remote_api_base()
    if not remote_api_base:
        return None

    request_headers = {"Accept": "application/json"}
    request_data = None
    request_method = "GET"
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
        request_data = json.dumps(payload).encode("utf-8")
        request_method = "POST"

    request = urllib.request.Request(
        f"{remote_api_base}{path}",
        data=request_data,
        headers=request_headers,
        method=request_method,
    )

    try:
        with urllib.request.urlopen(request, timeout=REMOTE_TIMEOUT_SECONDS) as response:
            raw_payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw_payload = exc.read().decode("utf-8", errors="replace")
        try:
            error_payload = json.loads(raw_payload) if raw_payload else {}
        except json.JSONDecodeError:
            error_payload = {}
        return {
            "error": error_payload.get("error") or f"Remote request failed: HTTP {exc.code}",
            "status_code": exc.code,
        }
    except OSError as exc:
        return {"error": f"Remote request failed: {exc}"}

    try:
        return json.loads(raw_payload) if raw_payload else {}
    except json.JSONDecodeError:
        return {"error": "Remote service returned invalid JSON."}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    _ensure_schema(connection)
    _cleanup_expired_sessions(connection)
    return connection


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workflow_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL UNIQUE COLLATE NOCASE,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            key_required INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            destroyed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS workflow_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_group_id INTEGER NOT NULL REFERENCES workflow_groups(id) ON DELETE CASCADE,
            access_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active',
            expiry_mode TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.commit()


def _cleanup_expired_sessions(connection: sqlite3.Connection) -> None:
    connection.execute(
        "DELETE FROM sessions WHERE expires_at <= ?",
        (_isoformat(_utcnow()),),
    )
    connection.commit()


def ensure_initialized() -> None:
    with _connect():
        pass


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
        dklen=32,
    ).hex()


def _serialize_user(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "created_at": row["created_at"],
    }


def _serialize_key(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "access_key": row["access_key"],
        "status": row["status"],
        "expiry_mode": row["expiry_mode"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _serialize_group(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "code": row["code"],
        "name": row["name"],
        "status": row["status"],
        "key_required": bool(row["key_required"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "destroyed_at": row["destroyed_at"],
        "keys": [],
    }


def _load_group_with_keys(connection: sqlite3.Connection, group_id: int) -> dict:
    group_row = connection.execute(
        "SELECT * FROM workflow_groups WHERE id = ?",
        (int(group_id),),
    ).fetchone()
    if group_row is None:
        raise KeyStoreError("Workflow group does not exist.")

    group = _serialize_group(group_row)
    key_rows = connection.execute(
        """
        SELECT *
        FROM workflow_keys
        WHERE workflow_group_id = ?
        ORDER BY created_at DESC
        """,
        (int(group_id),),
    ).fetchall()
    group["keys"] = [_serialize_key(row) for row in key_rows]
    return group


def register_user(username: str, password: str) -> dict:
    username = (username or "").strip()
    password = password or ""
    if len(username) < 3:
        raise KeyStoreError("Username must be at least 3 characters.")
    if len(password) < 6:
        raise KeyStoreError("Password must be at least 6 characters.")

    salt = secrets.token_hex(16)
    password_hash = _hash_password(password, salt)
    created_at = _isoformat(_utcnow())

    with _connect() as connection:
        try:
            connection.execute(
                """
                INSERT INTO users (username, password_salt, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, salt, password_hash, created_at),
            )
            connection.commit()
        except sqlite3.IntegrityError as exc:
            raise KeyStoreError("Username already exists.") from exc

        row = connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        return _serialize_user(row)


def login_user(username: str, password: str) -> tuple[str, dict]:
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        raise KeyStoreError("Username and password are required.")

    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if row is None:
            raise KeyStoreError("Invalid username or password.")

        expected_hash = row["password_hash"]
        actual_hash = _hash_password(password, row["password_salt"])
        if not hmac.compare_digest(expected_hash, actual_hash):
            raise KeyStoreError("Invalid username or password.")

        created_at = _utcnow()
        token = secrets.token_urlsafe(32)
        expires_at = created_at + timedelta(seconds=SESSION_MAX_AGE_SECONDS)
        connection.execute(
            """
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (token, int(row["id"]), _isoformat(created_at), _isoformat(expires_at)),
        )
        connection.commit()
        return token, _serialize_user(row)


def logout_user(session_token: str) -> None:
    if not session_token:
        return
    with _connect() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
        connection.commit()


def get_user_by_session(session_token: str) -> dict | None:
    if not session_token:
        return None

    with _connect() as connection:
        row = connection.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
              AND sessions.expires_at > ?
            """,
            (session_token, _isoformat(_utcnow())),
        ).fetchone()
        return _serialize_user(row)


def upsert_workflow_group(user_id: int, code: str, name: str) -> dict:
    code = (code or "").strip()
    name = (name or "").strip() or code
    if len(code) < 3:
        raise KeyStoreError("Workflow code must be at least 3 characters.")

    now = _isoformat(_utcnow())
    with _connect() as connection:
        existing = connection.execute(
            "SELECT * FROM workflow_groups WHERE code = ? COLLATE NOCASE",
            (code,),
        ).fetchone()
        if existing is not None and int(existing["user_id"]) != int(user_id):
            raise KeyStoreError("Workflow code already belongs to another account.")

        if existing is None:
            connection.execute(
                """
                INSERT INTO workflow_groups (
                    user_id, code, name, status, key_required, created_at, updated_at
                )
                VALUES (?, ?, ?, 'active', 1, ?, ?)
                """,
                (int(user_id), code, name, now, now),
            )
        else:
            if existing["status"] in {"deleted", "destroyed"}:
                connection.execute(
                    """
                    UPDATE workflow_groups
                    SET name = ?, status = 'active', key_required = 1, updated_at = ?, destroyed_at = NULL
                    WHERE id = ?
                    """,
                    (name, now, int(existing["id"])),
                )
            else:
                connection.execute(
                    """
                    UPDATE workflow_groups
                    SET name = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (name, now, int(existing["id"])),
                )
        connection.commit()

        row = connection.execute(
            "SELECT id FROM workflow_groups WHERE code = ? COLLATE NOCASE",
            (code,),
        ).fetchone()
        return _load_group_with_keys(connection, int(row["id"]))


def list_workflow_groups(user_id: int) -> list[dict]:
    with _connect() as connection:
        group_rows = connection.execute(
            """
            SELECT *
            FROM workflow_groups
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (int(user_id),),
        ).fetchall()

        groups = []
        for row in group_rows:
            groups.append(_load_group_with_keys(connection, int(row["id"])))
        return groups


def _generate_access_key() -> str:
    segments = [secrets.token_hex(2).upper() for _ in range(4)]
    return "XLJ-" + "-".join(segments)


def _resolve_expiry(expiry_mode: str) -> tuple[str, str | None]:
    expiry_mode = (expiry_mode or "").strip().lower() or "unlimited"
    if expiry_mode not in EXPIRY_MODES:
        raise KeyStoreError("Unsupported expiry mode.")
    delta = EXPIRY_MODES[expiry_mode]
    expires_at = None if delta is None else _isoformat(_utcnow() + delta)
    return expiry_mode, expires_at


def generate_workflow_key(user_id: int, group_id: int, expiry_mode: str) -> dict:
    expiry_mode, expires_at = _resolve_expiry(expiry_mode)
    now = _isoformat(_utcnow())

    with _connect() as connection:
        group_row = connection.execute(
            "SELECT * FROM workflow_groups WHERE id = ? AND user_id = ?",
            (int(group_id), int(user_id)),
        ).fetchone()
        if group_row is None:
            raise KeyStoreError("Workflow group does not exist.")
        if group_row["status"] != "active":
            raise KeyStoreError("Workflow group is not active.")

        access_key = _generate_access_key()
        connection.execute(
            """
            INSERT INTO workflow_keys (
                workflow_group_id, access_key, status, expiry_mode, expires_at, created_at, updated_at
            )
            VALUES (?, ?, 'active', ?, ?, ?, ?)
            """,
            (int(group_id), access_key, expiry_mode, expires_at, now, now),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM workflow_keys WHERE access_key = ?",
            (access_key,),
        ).fetchone()
        return _serialize_key(row)


def disable_workflow_group(user_id: int, group_id: int) -> dict:
    now = _isoformat(_utcnow())
    with _connect() as connection:
        group_row = connection.execute(
            "SELECT * FROM workflow_groups WHERE id = ? AND user_id = ?",
            (int(group_id), int(user_id)),
        ).fetchone()
        if group_row is None:
            raise KeyStoreError("Workflow group does not exist.")
        if group_row["status"] == "destroyed":
            raise KeyStoreError("Destroyed workflow groups cannot be disabled again.")

        connection.execute(
            """
            UPDATE workflow_groups
            SET status = 'disabled', updated_at = ?
            WHERE id = ?
            """,
            (now, int(group_id)),
        )
        connection.execute(
            """
            UPDATE workflow_keys
            SET status = 'disabled', updated_at = ?
            WHERE workflow_group_id = ?
            """,
            (now, int(group_id)),
        )
        connection.commit()
        return _load_group_with_keys(connection, int(group_id))


def destroy_workflow_group(user_id: int, group_id: int) -> dict:
    now = _isoformat(_utcnow())
    with _connect() as connection:
        group_row = connection.execute(
            "SELECT * FROM workflow_groups WHERE id = ? AND user_id = ?",
            (int(group_id), int(user_id)),
        ).fetchone()
        if group_row is None:
            raise KeyStoreError("Workflow group does not exist.")

        connection.execute(
            """
            UPDATE workflow_groups
            SET status = 'destroyed', updated_at = ?, destroyed_at = ?
            WHERE id = ?
            """,
            (now, now, int(group_id)),
        )
        connection.execute(
            """
            UPDATE workflow_keys
            SET status = 'destroyed', updated_at = ?
            WHERE workflow_group_id = ?
            """,
            (now, int(group_id)),
        )
        connection.commit()
        return _load_group_with_keys(connection, int(group_id))


def get_workflow_group_status(code: str) -> dict:
    code = (code or "").strip()
    if not code:
        return {"found": False, "status": "missing_group"}

    remote_payload = _remote_request_json(
        f"/xljworkflowcipher/api/key-groups/status?{urllib.parse.urlencode({'code': code})}"
    )
    if remote_payload is not None:
        if remote_payload.get("error"):
            return {"found": False, "status": "remote_error", "error": remote_payload["error"]}
        return remote_payload

    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM workflow_groups WHERE code = ? COLLATE NOCASE",
            (code,),
        ).fetchone()
        if row is None:
            return {"found": False, "status": "missing_group"}
        return {
            "found": True,
            "status": row["status"],
            "code": row["code"],
            "name": row["name"],
            "destroyed": row["status"] == "destroyed",
        }


def validate_access_key(code: str, access_key: str) -> dict:
    remote_api_base = _remote_api_base()
    access_key = (access_key or "").strip()
    if remote_api_base:
        if not access_key:
            return {"valid": False, "bypass": False, "status": "missing_key"}

        remote_payload = _remote_request_json(
            "/xljworkflowcipher/api/access/validate",
            {
                "key": access_key,
            },
        )
        if remote_payload is not None:
            if remote_payload.get("error"):
                return {
                    "valid": False,
                    "bypass": False,
                    "status": "remote_error",
                    "error": remote_payload["error"],
                }
            if "valid" in remote_payload or "bypass" in remote_payload:
                return remote_payload
            if remote_payload.get("ok") is False:
                return {
                    "valid": False,
                    "bypass": False,
                    "status": "invalid_key",
                    "error": remote_payload.get("error") or "Access key is invalid.",
                }
            return {
                "valid": True,
                "bypass": False,
                "status": "active",
                "key": access_key,
                **remote_payload,
            }

    group_status = get_workflow_group_status(code)
    if not group_status["found"]:
        return {"valid": False, "bypass": False, "status": "missing_group"}
    if group_status["status"] == "destroyed":
        return {"valid": True, "bypass": True, "status": "destroyed"}
    if group_status["status"] != "active":
        return {"valid": False, "bypass": False, "status": group_status["status"]}

    access_key = (access_key or "").strip()
    if not access_key:
        return {"valid": False, "bypass": False, "status": "missing_key"}

    with _connect() as connection:
        row = connection.execute(
            """
            SELECT workflow_keys.*, workflow_groups.code, workflow_groups.name
            FROM workflow_keys
            JOIN workflow_groups ON workflow_groups.id = workflow_keys.workflow_group_id
            WHERE workflow_groups.code = ? COLLATE NOCASE
              AND workflow_keys.access_key = ?
            """,
            (code, access_key),
        ).fetchone()
        if row is None:
            return {"valid": False, "bypass": False, "status": "invalid_key"}
        if row["status"] != "active":
            return {"valid": False, "bypass": False, "status": row["status"]}

        expires_at = _parse_datetime(row["expires_at"])
        if expires_at is not None and expires_at <= _utcnow():
            return {"valid": False, "bypass": False, "status": "expired"}

        return {
            "valid": True,
            "bypass": False,
            "status": "active",
            "workflow_code": row["code"],
            "workflow_name": row["name"],
            "expires_at": row["expires_at"],
        }

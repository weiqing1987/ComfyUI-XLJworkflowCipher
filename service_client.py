from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie

from .key_store import (
    KeyStoreError,
    SESSION_COOKIE_NAME,
    get_workflow_group_status,
    validate_access_key,
)


DEFAULT_API_TIMEOUT_SECONDS = float(
    os.getenv("XLJWORKFLOWCIPHER_API_TIMEOUT_SECONDS", "10")
)


def get_configured_api_base() -> str:
    return (os.getenv("XLJWORKFLOWCIPHER_API_BASE") or "").strip().rstrip("/")


def has_configured_api_base() -> bool:
    return bool(get_configured_api_base())


def get_configured_portal_url() -> str:
    configured = (os.getenv("XLJWORKFLOWCIPHER_PORTAL_URL") or "").strip()
    if configured:
        return configured

    api_base = get_configured_api_base()
    if not api_base:
        return ""
    return f"{api_base}/xljworkflowcipher/portal"


def _extract_session_token(headers) -> str:
    if headers is None:
        return ""
    for value in headers.get_all("Set-Cookie", []):
        cookie = SimpleCookie()
        cookie.load(value)
        morsel = cookie.get(SESSION_COOKIE_NAME)
        if morsel and morsel.value:
            return morsel.value.strip()
    return ""


def _remote_request(
    method: str,
    path: str,
    payload: dict | None = None,
    session_token: str = "",
) -> dict:
    api_base = get_configured_api_base()
    if not api_base:
        raise KeyStoreError("License service is not configured.")

    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if session_token:
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={session_token}"

    request = urllib.request.Request(
        url=f"{api_base}{path}",
        method=method.upper(),
        data=body,
        headers=headers,
    )

    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_API_TIMEOUT_SECONDS) as response:
            charset = response.headers.get_content_charset("utf-8")
            raw = response.read().decode(charset)
            response_session_token = _extract_session_token(response.headers)
    except urllib.error.HTTPError as exc:
        charset = exc.headers.get_content_charset("utf-8") if exc.headers else "utf-8"
        raw = exc.read().decode(charset, errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {}
        message = payload.get("error") or f"License service returned HTTP {exc.code}."
        raise KeyStoreError(message) from exc
    except urllib.error.URLError as exc:
        raise KeyStoreError(f"License service is unavailable: {exc.reason}") from exc
    except Exception as exc:
        raise KeyStoreError(f"License service request failed: {exc}") from exc

    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise KeyStoreError("License service returned invalid JSON.") from exc

    if payload.get("error"):
        raise KeyStoreError(payload["error"])
    return {
        "payload": payload,
        "session_token": response_session_token,
    }


def fetch_workflow_group_status(code: str) -> dict:
    if not has_configured_api_base():
        return get_workflow_group_status(code)

    query = urllib.parse.urlencode({"code": (code or "").strip()})
    return _remote_request(
        "GET",
        f"/xljworkflowcipher/api/key-groups/status?{query}",
    )["payload"]


def check_access_key(code: str, access_key: str) -> dict:
    if not has_configured_api_base():
        return validate_access_key(code, access_key)

    return _remote_request(
        "POST",
        "/xljworkflowcipher/api/access/validate",
        {
            "code": (code or "").strip(),
            "access_key": (access_key or "").strip(),
        },
    )["payload"]


def register_portal_user(username: str, password: str) -> tuple[dict, str]:
    response = _remote_request(
        "POST",
        "/xljworkflowcipher/api/register",
        {
            "username": (username or "").strip(),
            "password": password or "",
        },
    )
    return response["payload"], response["session_token"]


def login_portal_user(username: str, password: str) -> tuple[dict, str]:
    response = _remote_request(
        "POST",
        "/xljworkflowcipher/api/login",
        {
            "username": (username or "").strip(),
            "password": password or "",
        },
    )
    return response["payload"], response["session_token"]


def logout_portal_user(session_token: str) -> dict:
    return _remote_request(
        "POST",
        "/xljworkflowcipher/api/logout",
        session_token=(session_token or "").strip(),
    )["payload"]


def fetch_portal_me(session_token: str) -> dict:
    return _remote_request(
        "GET",
        "/xljworkflowcipher/api/me",
        session_token=(session_token or "").strip(),
    )["payload"]


def list_portal_workflows(session_token: str) -> dict:
    return _remote_request(
        "GET",
        "/xljworkflowcipher/api/workflows",
        session_token=(session_token or "").strip(),
    )["payload"]


def upsert_portal_workflow(session_token: str, code: str, name: str) -> dict:
    return _remote_request(
        "POST",
        "/xljworkflowcipher/api/workflows",
        {
            "code": (code or "").strip(),
            "name": (name or "").strip(),
        },
        session_token=(session_token or "").strip(),
    )["payload"]


def generate_portal_workflow_key(session_token: str, group_id: int, expiry_mode: str) -> dict:
    return _remote_request(
        "POST",
        f"/xljworkflowcipher/api/workflows/{int(group_id)}/keys",
        {"expiry_mode": (expiry_mode or "").strip() or "unlimited"},
        session_token=(session_token or "").strip(),
    )["payload"]


def disable_portal_workflow_group(session_token: str, group_id: int) -> dict:
    return _remote_request(
        "POST",
        f"/xljworkflowcipher/api/workflows/{int(group_id)}/disable",
        session_token=(session_token or "").strip(),
    )["payload"]


def destroy_portal_workflow_group(session_token: str, group_id: int) -> dict:
    return _remote_request(
        "POST",
        f"/xljworkflowcipher/api/workflows/{int(group_id)}/destroy",
        session_token=(session_token or "").strip(),
    )["payload"]

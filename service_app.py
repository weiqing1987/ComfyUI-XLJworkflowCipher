from __future__ import annotations

import os
from pathlib import Path

from aiohttp import web

try:
    from .key_store import (
        KeyStoreError,
        SESSION_COOKIE_NAME,
        SESSION_MAX_AGE_SECONDS,
        destroy_workflow_group,
        disable_workflow_group,
        ensure_initialized,
        generate_workflow_key,
        get_user_by_session,
        get_workflow_group_status,
        list_workflow_groups,
        login_user,
        logout_user,
        register_user,
        upsert_workflow_group,
        validate_access_key,
    )
except ImportError:
    from key_store import (
        KeyStoreError,
        SESSION_COOKIE_NAME,
        SESSION_MAX_AGE_SECONDS,
        destroy_workflow_group,
        disable_workflow_group,
        ensure_initialized,
        generate_workflow_key,
        get_user_by_session,
        get_workflow_group_status,
        list_workflow_groups,
        login_user,
        logout_user,
        register_user,
        upsert_workflow_group,
        validate_access_key,
    )


PORTAL_DIR = Path(__file__).resolve().parent / "portal"


def _cookie_secure_enabled() -> bool:
    return (os.getenv("XLJWORKFLOWCIPHER_COOKIE_SECURE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _error_response(message, status=400):
    return web.json_response({"error": str(message)}, status=status)


def _session_token(request):
    return (request.cookies.get(SESSION_COOKIE_NAME) or "").strip()


def _authenticated_user(request):
    token = _session_token(request)
    user = get_user_by_session(token)
    if user is None:
        raise KeyStoreError("Please log in first.")
    return user, token


def _session_response(payload, session_token=None, clear_session=False):
    response = web.json_response(payload)
    if session_token:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="Lax",
            secure=_cookie_secure_enabled(),
        )
    if clear_session:
        response.del_cookie(SESSION_COOKIE_NAME)
    return response


async def xljworkflowcipher_register(request):
    try:
        json_data = await request.json()
        register_user(json_data.get("username", ""), json_data.get("password", ""))
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response({"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_login(request):
    try:
        json_data = await request.json()
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response({"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_logout(request):
    try:
        _, token = _authenticated_user(request)
        logout_user(token)
        return _session_response({"ok": True}, clear_session=True)
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_me(request):
    try:
        user, _token = _authenticated_user(request)
        groups = list_workflow_groups(user["id"])
        return web.json_response({"user": user, "groups": groups})
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_list_workflows(request):
    try:
        user, _token = _authenticated_user(request)
        return web.json_response({"groups": list_workflow_groups(user["id"])})
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_upsert_workflow(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        group = upsert_workflow_group(
            user["id"],
            json_data.get("code", ""),
            json_data.get("name", ""),
        )
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_generate_key(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        key_data = generate_workflow_key(
            user["id"],
            int(request.match_info["group_id"]),
            json_data.get("expiry_mode", "unlimited"),
        )
        return web.json_response({"key": key_data})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_disable_group(request):
    try:
        user, _token = _authenticated_user(request)
        group = disable_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_destroy_group(request):
    try:
        user, _token = _authenticated_user(request)
        group = destroy_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_group_status(request):
    try:
        code = request.query.get("code", "")
        return web.json_response(get_workflow_group_status(code))
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_access_validate(request):
    try:
        json_data = await request.json()
        return web.json_response(
            validate_access_key(
                json_data.get("code", ""),
                json_data.get("access_key", ""),
            )
        )
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def xljworkflowcipher_health(request):
    return web.json_response({"ok": True})


async def xljworkflowcipher_root(request):
    raise web.HTTPFound("/xljworkflowcipher/portal")


async def xljworkflowcipher_portal(request):
    return web.FileResponse(PORTAL_DIR / "index.html")


async def xljworkflowcipher_portal_styles(request):
    return web.FileResponse(PORTAL_DIR / "styles.css")


async def xljworkflowcipher_portal_app(request):
    return web.FileResponse(PORTAL_DIR / "app.js")


def create_app() -> web.Application:
    ensure_initialized()
    app = web.Application()
    app.router.add_get("/", xljworkflowcipher_root)
    app.router.add_get("/xljworkflowcipher/api/health", xljworkflowcipher_health)
    app.router.add_post("/xljworkflowcipher/api/register", xljworkflowcipher_register)
    app.router.add_post("/xljworkflowcipher/api/login", xljworkflowcipher_login)
    app.router.add_post("/xljworkflowcipher/api/logout", xljworkflowcipher_logout)
    app.router.add_get("/xljworkflowcipher/api/me", xljworkflowcipher_me)
    app.router.add_get("/xljworkflowcipher/api/workflows", xljworkflowcipher_list_workflows)
    app.router.add_post("/xljworkflowcipher/api/workflows", xljworkflowcipher_upsert_workflow)
    app.router.add_post(
        "/xljworkflowcipher/api/workflows/{group_id}/keys",
        xljworkflowcipher_generate_key,
    )
    app.router.add_post(
        "/xljworkflowcipher/api/workflows/{group_id}/disable",
        xljworkflowcipher_disable_group,
    )
    app.router.add_post(
        "/xljworkflowcipher/api/workflows/{group_id}/destroy",
        xljworkflowcipher_destroy_group,
    )
    app.router.add_get("/xljworkflowcipher/api/key-groups/status", xljworkflowcipher_group_status)
    app.router.add_post("/xljworkflowcipher/api/access/validate", xljworkflowcipher_access_validate)
    app.router.add_get("/xljworkflowcipher/portal", xljworkflowcipher_portal)
    app.router.add_get("/xljworkflowcipher/portal/styles.css", xljworkflowcipher_portal_styles)
    app.router.add_get("/xljworkflowcipher/portal/app.js", xljworkflowcipher_portal_app)
    return app


def main():
    host = (os.getenv("XLJWORKFLOWCIPHER_SERVICE_HOST") or "0.0.0.0").strip()
    port = int((os.getenv("XLJWORKFLOWCIPHER_SERVICE_PORT") or "8218").strip())
    web.run_app(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()

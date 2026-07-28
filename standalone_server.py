"""
XLJworkflowCipher standalone backend service.

Provides creator account, workflow group, and access-key APIs together with the
portal static files. This variant is intended for standalone deployment behind
an HTTPS reverse proxy.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from aiohttp import web

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from key_store import (  # noqa: E402
    change_user_password,
    KeyStoreError,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    delete_workflow_group_forever,
    delete_workflow_key,
    destroy_workflow_group,
    disable_workflow_group,
    generate_workflow_key,
    get_user_by_session,
    get_workflow_group_status,
    list_workflow_groups,
    login_user,
    logout_user,
    register_user,
    restore_workflow_group,
    upsert_workflow_group,
    update_workflow_key_note,
    validate_access_key,
)


PORTAL_DIR = BASE_DIR / "portal"
logger = logging.getLogger("xljworkflowcipher")


def _error_response(message, status=400):
    return web.json_response({"error": str(message)}, status=status)


def _configured_flag(name):
    value = (os.getenv(name) or "").strip().lower()
    if not value:
        return None
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return None


def _request_is_secure(request):
    if request is None:
        return False
    forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip().lower()
    if forwarded_proto:
        return forwarded_proto == "https"
    return bool(request.secure)


def _cookie_secure_enabled(request=None):
    configured = _configured_flag("XLJWORKFLOWCIPHER_COOKIE_SECURE")
    if configured is not None:
        return configured
    return _request_is_secure(request)


def _cookie_samesite_value(request=None):
    configured = (os.getenv("XLJWORKFLOWCIPHER_COOKIE_SAMESITE") or "").strip()
    if configured:
        return configured
    if _cookie_secure_enabled(request):
        return "None"
    return "Lax"


def _allowed_cors_origins():
    origins = {
        "http://127.0.0.1:8188",
        "http://localhost:8188",
    }
    configured = (os.getenv("XLJWORKFLOWCIPHER_CORS_ALLOW_ORIGINS") or "").strip()
    if not configured:
        return origins
    for value in configured.split(","):
        origin = value.strip()
        if origin:
            origins.add(origin.rstrip("/"))
    return origins


def _cors_origin(request):
    origin = (request.headers.get("Origin") or "").strip().rstrip("/")
    if not origin:
        return ""
    return origin if origin in _allowed_cors_origins() else ""


def _apply_cors_headers(request, response):
    origin = _cors_origin(request)
    if not origin:
        return response
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Vary"] = "Origin"
    return response


@web.middleware
async def _cors_middleware(request, handler):
    response = await handler(request)
    return _apply_cors_headers(request, response)


def _session_token(request):
    return (request.cookies.get(SESSION_COOKIE_NAME) or "").strip()


def _authenticated_user(request):
    token = _session_token(request)
    user = get_user_by_session(token)
    if user is None:
        raise KeyStoreError("Please log in first.")
    return user, token


def _session_response(request, payload, session_token=None, clear_session=False):
    response = web.json_response(payload)
    if session_token:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_token,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite=_cookie_samesite_value(request),
            secure=_cookie_secure_enabled(request),
        )
    if clear_session:
        response.del_cookie(SESSION_COOKIE_NAME)
    return response


async def api_options(request):
    return web.Response(status=204)


async def api_register(request):
    try:
        json_data = await request.json()
        register_user(json_data.get("username", ""), json_data.get("password", ""))
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response(request, {"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_login(request):
    try:
        json_data = await request.json()
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response(request, {"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_logout(request):
    try:
        _, token = _authenticated_user(request)
        logout_user(token)
        return _session_response(request, {"ok": True}, clear_session=True)
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_change_password(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        updated_user = change_user_password(
            user["id"],
            json_data.get("current_password", ""),
            json_data.get("new_password", ""),
        )
        return web.json_response({"user": updated_user, "ok": True})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_me(request):
    try:
        user, _token = _authenticated_user(request)
        groups = list_workflow_groups(user["id"])
        return web.json_response({"user": user, "groups": groups})
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_list_workflows(request):
    try:
        user, _token = _authenticated_user(request)
        return web.json_response({"groups": list_workflow_groups(user["id"])})
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


def _requested_key_count(payload):
    try:
        count = int(payload.get("key_count", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(count, 20))


def _requested_expiry_mode(payload):
    raw_mode = (payload.get("expiry_mode") or "").strip().lower()
    if raw_mode:
        return raw_mode

    try:
        validity_days = int(payload.get("key_validity_days", 0) or 0)
    except (TypeError, ValueError):
        validity_days = 0

    if validity_days >= 30:
        return "month"
    if validity_days >= 7:
        return "week"
    if validity_days >= 1:
        return "day"
    return "unlimited"


async def api_upsert_workflow(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        group = upsert_workflow_group(
            user["id"],
            json_data.get("code", ""),
            json_data.get("name", ""),
        )
        generated_keys = []
        key_count = _requested_key_count(json_data)
        expiry_mode = _requested_expiry_mode(json_data)
        note = json_data.get("note", "")
        for _ in range(key_count):
            generated_keys.append(
                generate_workflow_key(user["id"], int(group["id"]), expiry_mode, note)
            )
        if generated_keys:
            group = next(
                (item for item in list_workflow_groups(user["id"]) if int(item["id"]) == int(group["id"])),
                group,
            )
        return web.json_response({"group": group, "keys": generated_keys})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_generate_key(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        key_data = generate_workflow_key(
            user["id"],
            int(request.match_info["group_id"]),
            json_data.get("expiry_mode", "unlimited"),
            json_data.get("note", ""),
        )
        return web.json_response({"key": key_data})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_delete_key(request):
    try:
        user, _token = _authenticated_user(request)
        group = delete_workflow_key(
            user["id"],
            int(request.match_info["group_id"]),
            int(request.match_info["key_id"]),
        )
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_update_key_note(request):
    try:
        user, _token = _authenticated_user(request)
        json_data = await request.json()
        key_data = update_workflow_key_note(
            user["id"],
            int(request.match_info["group_id"]),
            int(request.match_info["key_id"]),
            json_data.get("note", ""),
        )
        return web.json_response({"key": key_data})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_disable_group(request):
    try:
        user, _token = _authenticated_user(request)
        group = disable_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_destroy_group(request):
    try:
        user, _token = _authenticated_user(request)
        group = destroy_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_restore_group(request):
    try:
        user, _token = _authenticated_user(request)
        group = restore_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_delete_group_forever(request):
    try:
        user, _token = _authenticated_user(request)
        delete_workflow_group_forever(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"ok": True})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_group_status(request):
    try:
        code = request.query.get("code", "")
        return web.json_response(get_workflow_group_status(code))
    except Exception as exc:
        return _error_response(exc, status=500)


async def api_access_validate(request):
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


async def api_frontend_config(request):
    portal_url = f"{request.scheme}://{request.host}/xljworkflowcipher/portal"
    return web.json_response(
        {
            "api_base": f"{request.scheme}://{request.host}",
            "portal_url": portal_url,
            "remote_enabled": True,
        }
    )


async def portal_index(request):
    try:
        return web.Response(
            text=(PORTAL_DIR / "index.html").read_text(encoding="utf-8"),
            content_type="text/html",
        )
    except Exception as exc:
        logger.error("Failed to serve portal index: %s", exc)
        raise web.HTTPNotFound()


async def portal_recycle(request):
    try:
        return web.Response(
            text=(PORTAL_DIR / "recycle.html").read_text(encoding="utf-8"),
            content_type="text/html",
        )
    except Exception as exc:
        logger.error("Failed to serve recycle page: %s", exc)
        raise web.HTTPNotFound()


async def portal_expiring(request):
    try:
        return web.Response(
            text=(PORTAL_DIR / "expiring.html").read_text(encoding="utf-8"),
            content_type="text/html",
        )
    except Exception as exc:
        logger.error("Failed to serve expiring page: %s", exc)
        raise web.HTTPNotFound()


async def portal_styles(request):
    try:
        return web.Response(
            text=(PORTAL_DIR / "styles.css").read_text(encoding="utf-8"),
            content_type="text/css",
        )
    except Exception as exc:
        logger.error("Failed to serve portal styles: %s", exc)
        raise web.HTTPNotFound()


async def portal_app(request):
    try:
        return web.Response(
            text=(PORTAL_DIR / "app.js").read_text(encoding="utf-8"),
            content_type="application/javascript",
        )
    except Exception as exc:
        logger.error("Failed to serve portal app.js: %s", exc)
        raise web.HTTPNotFound()


def create_app():
    from key_store import ensure_initialized

    ensure_initialized()
    app = web.Application(middlewares=[_cors_middleware])

    app.router.add_route("OPTIONS", "/{path_info:.*}", api_options)

    app.router.add_post("/xljworkflowcipher/api/register", api_register)
    app.router.add_post("/xljworkflowcipher/api/login", api_login)
    app.router.add_post("/xljworkflowcipher/api/logout", api_logout)
    app.router.add_post("/xljworkflowcipher/api/change-password", api_change_password)
    app.router.add_get("/xljworkflowcipher/api/me", api_me)
    app.router.add_get("/xljworkflowcipher/api/workflows", api_list_workflows)
    app.router.add_post("/xljworkflowcipher/api/workflows", api_upsert_workflow)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/keys", api_generate_key)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/keys/{key_id}/delete", api_delete_key)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/keys/{key_id}/note", api_update_key_note)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/disable", api_disable_group)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/destroy", api_destroy_group)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/restore", api_restore_group)
    app.router.add_post("/xljworkflowcipher/api/workflows/{group_id}/delete", api_delete_group_forever)
    app.router.add_get("/xljworkflowcipher/api/key-groups/status", api_group_status)
    app.router.add_post("/xljworkflowcipher/api/access/validate", api_access_validate)
    app.router.add_get("/xljworkflowcipher/api/frontend-config", api_frontend_config)

    app.router.add_get("/xljworkflowcipher/portal", portal_index)
    app.router.add_get("/xljworkflowcipher/portal/recycle", portal_recycle)
    app.router.add_get("/xljworkflowcipher/portal/expiring", portal_expiring)
    app.router.add_get("/xljworkflowcipher/portal/styles.css", portal_styles)
    app.router.add_get("/xljworkflowcipher/portal/app.js", portal_app)

    return app


def main():
    parser = argparse.ArgumentParser(description="XLJworkflowCipher Standalone Backend Server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=8218, help="Listen port")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(message)s",
        stream=sys.stderr,
    )
    logger.info("Starting server on %s:%s", args.host, args.port)

    app = create_app()

    async def start():
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, args.host, args.port)
        await site.start()
        logger.info("Server running on http://%s:%s", args.host, args.port)
        logger.info("Portal: http://%s:%s/xljworkflowcipher/portal", args.host, args.port)
        return runner

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runner = loop.run_until_complete(start())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(runner.cleanup())
        loop.close()


if __name__ == "__main__":
    main()

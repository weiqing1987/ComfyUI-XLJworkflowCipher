import os
from pathlib import Path

import server
from aiohttp import web

from .key_store import (
    KeyStoreError,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    destroy_workflow_group,
    disable_workflow_group,
    ensure_initialized,
    generate_workflow_key,
    get_user_by_session,
    login_user,
    logout_user,
    register_user,
    list_workflow_groups,
    upsert_workflow_group,
)
from .service_client import (
    check_access_key,
    destroy_portal_workflow_group,
    fetch_workflow_group_status,
    fetch_portal_me,
    generate_portal_workflow_key,
    get_configured_api_base,
    has_configured_api_base,
    list_portal_workflows,
    login_portal_user,
    logout_portal_user,
    register_portal_user,
    upsert_portal_workflow,
    disable_portal_workflow_group,
)
from .workflow_cipher import (
    WorkflowCipherBridgeNode,
    WorkflowCipherDecryptNode,
    WorkflowCipherEncryptNode,
    WorkflowCipherRandomSeedNode,
    WorkflowCipherVaultNode,
    decrypt_selection_to_shell_workflow,
    encrypt_selection_to_shell_workflow,
)


PORTAL_DIR = Path(__file__).resolve().parent / "portal"
ensure_initialized()


def _error_response(message, status=400, clear_session=False):
    response = web.json_response({"error": str(message)}, status=status)
    if clear_session:
        response.del_cookie(SESSION_COOKIE_NAME)
    return response


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
        )
    if clear_session:
        response.del_cookie(SESSION_COOKIE_NAME)
    return response


def _normalized_external_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    return value.rstrip("/")


def _frontend_config_payload():
    api_base = _normalized_external_url(get_configured_api_base() or os.getenv("XLJWORKFLOWCIPHER_API_BASE"))
    return {
        "api_base": api_base,
        "portal_url": "/xljworkflowcipher/portal",
        "remote_enabled": bool(api_base),
    }


async def _encrypt_selection_response(request):
    json_data = await request.json()
    return encrypt_selection_to_shell_workflow(
        workflow=json_data.get("workflow"),
        prompt=json_data.get("prompt") or json_data.get("output"),
        selected_node_ids=json_data.get("selected_node_ids") or [],
        passphrase=json_data.get("passphrase", ""),
        template_id=json_data.get("template_id"),
        node_title=json_data.get("node_title"),
        key_required=bool(json_data.get("key_required")),
        key_group=json_data.get("key_group"),
    )


async def _decrypt_selection_response(request):
    json_data = await request.json()
    return decrypt_selection_to_shell_workflow(
        workflow=json_data.get("workflow"),
        shell_node_id=json_data.get("shell_node_id"),
        passphrase=json_data.get("passphrase", ""),
    )


@server.PromptServer.instance.routes.post("/xljworkflowcipher/encrypt_selection")
@server.PromptServer.instance.routes.post("/workflow_cipher/encrypt_selection")
async def workflow_cipher_encrypt_selection(request):
    try:
        result = await _encrypt_selection_response(request)
        return web.json_response(result)
    except ValueError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/decrypt_selection")
@server.PromptServer.instance.routes.post("/workflow_cipher/decrypt_selection")
async def workflow_cipher_decrypt_selection(request):
    try:
        result = await _decrypt_selection_response(request)
        return web.json_response(result)
    except ValueError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/register")
async def xljworkflowcipher_register(request):
    try:
        json_data = await request.json()
        if has_configured_api_base():
            payload, session_token = register_portal_user(
                json_data.get("username", ""),
                json_data.get("password", ""),
            )
            return _session_response(payload, session_token=session_token)
        register_user(json_data.get("username", ""), json_data.get("password", ""))
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response({"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/login")
async def xljworkflowcipher_login(request):
    try:
        json_data = await request.json()
        if has_configured_api_base():
            payload, session_token = login_portal_user(
                json_data.get("username", ""),
                json_data.get("password", ""),
            )
            return _session_response(payload, session_token=session_token)
        session_token, user = login_user(json_data.get("username", ""), json_data.get("password", ""))
        return _session_response({"user": user}, session_token=session_token)
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/logout")
async def xljworkflowcipher_logout(request):
    try:
        token = _session_token(request)
        if has_configured_api_base():
            if token:
                try:
                    logout_portal_user(token)
                except KeyStoreError:
                    pass
            return _session_response({"ok": True}, clear_session=True)
        _, token = _authenticated_user(request)
        logout_user(token)
        return _session_response({"ok": True}, clear_session=True)
    except KeyStoreError as exc:
        return _error_response(exc, status=401)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.get("/xljworkflowcipher/api/me")
async def xljworkflowcipher_me(request):
    try:
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(fetch_portal_me(token))
        user, _token = _authenticated_user(request)
        groups = list_workflow_groups(user["id"])
        return web.json_response({"user": user, "groups": groups})
    except KeyStoreError as exc:
        return _error_response(exc, status=401, clear_session=True)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.get("/xljworkflowcipher/api/workflows")
async def xljworkflowcipher_list_workflows(request):
    try:
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(list_portal_workflows(token))
        user, _token = _authenticated_user(request)
        return web.json_response({"groups": list_workflow_groups(user["id"])})
    except KeyStoreError as exc:
        return _error_response(exc, status=401, clear_session=True)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/workflows")
async def xljworkflowcipher_upsert_workflow(request):
    try:
        json_data = await request.json()
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(
                upsert_portal_workflow(
                    token,
                    json_data.get("code", ""),
                    json_data.get("name", ""),
                )
            )
        user, _token = _authenticated_user(request)
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


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/workflows/{group_id}/keys")
async def xljworkflowcipher_generate_key(request):
    try:
        json_data = await request.json()
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(
                generate_portal_workflow_key(
                    token,
                    int(request.match_info["group_id"]),
                    json_data.get("expiry_mode", "unlimited"),
                )
            )
        user, _token = _authenticated_user(request)
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


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/workflows/{group_id}/disable")
async def xljworkflowcipher_disable_group(request):
    try:
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(
                disable_portal_workflow_group(
                    token,
                    int(request.match_info["group_id"]),
                )
            )
        user, _token = _authenticated_user(request)
        group = disable_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/workflows/{group_id}/destroy")
async def xljworkflowcipher_destroy_group(request):
    try:
        if has_configured_api_base():
            token = _session_token(request)
            if not token:
                raise KeyStoreError("Please log in first.")
            return web.json_response(
                destroy_portal_workflow_group(
                    token,
                    int(request.match_info["group_id"]),
                )
            )
        user, _token = _authenticated_user(request)
        group = destroy_workflow_group(user["id"], int(request.match_info["group_id"]))
        return web.json_response({"group": group})
    except KeyStoreError as exc:
        return _error_response(exc, status=400)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.get("/xljworkflowcipher/api/key-groups/status")
async def xljworkflowcipher_group_status(request):
    try:
        code = request.query.get("code", "")
        return web.json_response(fetch_workflow_group_status(code))
    except KeyStoreError as exc:
        return _error_response(exc, status=502)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/api/access/validate")
async def xljworkflowcipher_access_validate(request):
    try:
        json_data = await request.json()
        return web.json_response(
            check_access_key(
                json_data.get("code", ""),
                json_data.get("access_key", ""),
            )
        )
    except KeyStoreError as exc:
        return _error_response(exc, status=502)
    except Exception as exc:
        return _error_response(exc, status=500)


@server.PromptServer.instance.routes.get("/xljworkflowcipher/api/frontend-config")
async def xljworkflowcipher_frontend_config(request):
    return web.json_response(_frontend_config_payload())


@server.PromptServer.instance.routes.get("/xljworkflowcipher/portal")
async def xljworkflowcipher_portal(request):
    return web.FileResponse(PORTAL_DIR / "index.html")


@server.PromptServer.instance.routes.get("/xljworkflowcipher/portal/styles.css")
async def xljworkflowcipher_portal_styles(request):
    return web.FileResponse(PORTAL_DIR / "styles.css")


@server.PromptServer.instance.routes.get("/xljworkflowcipher/portal/app.js")
async def xljworkflowcipher_portal_app(request):
    return web.FileResponse(PORTAL_DIR / "app.js")


NODE_CLASS_MAPPINGS = {
    "WorkflowCipherEncryptNode": WorkflowCipherEncryptNode,
    "WorkflowCipherBridgeNode": WorkflowCipherBridgeNode,
    "WorkflowCipherDecryptNode": WorkflowCipherDecryptNode,
    "WorkflowCipherVaultNode": WorkflowCipherVaultNode,
    "WorkflowCipherRandomSeedNode": WorkflowCipherRandomSeedNode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "WorkflowCipherEncryptNode": "XLJworkflowCipher Encrypt",
    "WorkflowCipherBridgeNode": "XLJworkflowCipher Bridge",
    "WorkflowCipherDecryptNode": "XLJworkflowCipher Decrypt",
    "WorkflowCipherVaultNode": "ComfyUI-XLJworkflowCipher",
    "WorkflowCipherRandomSeedNode": "XLJworkflowCipher Random Seed",
}

WEB_DIRECTORY = "./web"

__all__ = [
    "NODE_CLASS_MAPPINGS",
    "NODE_DISPLAY_NAME_MAPPINGS",
    "WEB_DIRECTORY",
]

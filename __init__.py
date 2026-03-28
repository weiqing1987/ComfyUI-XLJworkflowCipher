from .workflow_cipher import (
    WorkflowCipherBridgeNode,
    WorkflowCipherDecryptNode,
    WorkflowCipherEncryptNode,
    WorkflowCipherRandomSeedNode,
    WorkflowCipherVaultNode,
    decrypt_selection_to_shell_workflow,
    encrypt_selection_to_shell_workflow,
)
import server
from aiohttp import web


async def _encrypt_selection_response(request):
    json_data = await request.json()
    return encrypt_selection_to_shell_workflow(
        workflow=json_data.get("workflow"),
        prompt=json_data.get("prompt") or json_data.get("output"),
        selected_node_ids=json_data.get("selected_node_ids") or [],
        passphrase=json_data.get("passphrase", ""),
        template_id=json_data.get("template_id"),
        node_title=json_data.get("node_title"),
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
        return web.json_response({"error": str(exc)}, status=400)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


@server.PromptServer.instance.routes.post("/xljworkflowcipher/decrypt_selection")
@server.PromptServer.instance.routes.post("/workflow_cipher/decrypt_selection")
async def workflow_cipher_decrypt_selection(request):
    try:
        result = await _decrypt_selection_response(request)
        return web.json_response(result)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


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

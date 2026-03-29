# ComfyUI-XLJworkflowCipher

Workflow encryption for ComfyUI with two operating modes:

- free local mode: creators encrypt locally and distribute encrypted workflow files directly
- licensed mode: creators still encrypt locally, but runtime authorization is validated by your website

The core rule for the licensed mode MVP is simple:

- workflow files stay local
- creators distribute the encrypted JSON themselves
- your website manages accounts, workflow groups, access keys, and validation
- your website does not need the workflow JSON or encrypted payload

## MVP architecture

### Free local mode

- Encrypt inside ComfyUI.
- Share the encrypted workflow JSON directly.
- No website is required.

### Licensed mode

- Encrypt inside ComfyUI.
- Share the encrypted workflow JSON directly.
- Customer imports the file into ComfyUI.
- The plugin sends `workflow_code + access_key` to your website for validation before execution.

Set `XLJWORKFLOWCIPHER_API_BASE` in the ComfyUI process to enable remote validation mode.

## Current security boundary

This plugin hides nodes, parameters, and model choices from normal users, but the current MVP is not hardened DRM.

- The encrypted payload is embedded in the workflow JSON.
- The runtime passphrase is still stored locally as `workflowcipher_runtime_key` so the workflow can run without asking for the original password every time.
- Remote validation currently controls authorization, not perfect extraction resistance.

That means the platform can avoid storing creator workflows, but a sufficiently technical customer may still reverse-engineer the local file.

## Nodes

### ComfyUI-XLJworkflowCipher

Selection-based encryption inside the current workflow.

- `password`: leave blank to run normally; enter the original passphrase to visually restore hidden nodes
- `access_key`: required only when key mode is enabled for that encrypted workflow

### XLJworkflowCipher Encrypt + Bridge + Decrypt

Flow-based export mode.

- `XLJworkflowCipher Encrypt`: marks where public inputs enter the hidden graph
- `XLJworkflowCipher Bridge`: marks where private outputs leave the hidden graph
- `XLJworkflowCipher Decrypt`: shell node in the exported workflow
- `XLJworkflowCipher Random Seed`: utility node

## Standalone license service

`service_app.py` starts an `aiohttp` service that exposes the same portal and API paths used by the plugin:

- `/xljworkflowcipher/portal`
- `/xljworkflowcipher/api/register`
- `/xljworkflowcipher/api/login`
- `/xljworkflowcipher/api/workflows`
- `/xljworkflowcipher/api/workflows/{group_id}/keys`
- `/xljworkflowcipher/api/key-groups/status`
- `/xljworkflowcipher/api/access/validate`

Default startup:

```bash
python service_app.py
```

Default bind:

- host: `0.0.0.0`
- port: `8218`

Install dependency if needed:

```bash
pip install -r service_requirements.txt
```

Environment variables are listed in `service.env.example`.

## Plugin configuration

### Local-only mode

Do not set `XLJWORKFLOWCIPHER_API_BASE`.

### Remote-license mode

Set these in the ComfyUI process environment:

```bash
XLJWORKFLOWCIPHER_API_BASE=https://your-domain.com
XLJWORKFLOWCIPHER_PORTAL_URL=https://your-domain.com/xljworkflowcipher/portal
```

When configured:

- runtime key-group status checks use your website
- runtime access-key validation uses your website
- clicking the portal button in ComfyUI redirects to your website portal

## Database

The local key store and standalone service both use SQLite by default. The database path can be overridden with:

```bash
XLJWORKFLOWCIPHER_DB_PATH=/absolute/path/to/xljworkflowcipher.sqlite3
```

SQLite is sufficient for an MVP or low-concurrency deployment. If you later move to public multi-user scale, migrate the service to a server database.

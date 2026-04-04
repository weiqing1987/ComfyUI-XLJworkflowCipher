# ComfyUI-XLJworkflowCipher

Workflow encryption nodes for ComfyUI. This plugin lets creators hide private nodes and model parameters while still allowing end users to run the workflow normally.

This project is inspired by the graph-shell pattern used by `RiceRound/ComfyUI_CryptoCat`, but keeps the encrypted payload embedded directly inside the exported workflow.

## Features

- Selection-based workflow encryption
- Optional access-key validation
- Remote workflow and license backend support
- Creator portal integration
- Local decryption for creators who know the passphrase

## Nodes

### ComfyUI-XLJworkflowCipher

Encrypts selected nodes directly inside the current workflow and replaces them with a single vault node.

Inputs:
- Up to 16 public inputs

Outputs:
- Up to 16 public outputs

Widgets:
- `password`: leave blank for normal execution; enter the original passphrase to visually restore hidden nodes
- `access_key`: shown only when key mode is enabled

### XLJworkflowCipher Encrypt + Bridge + Decrypt

An alternative three-node flow for explicit packing and restoring.

- `XLJworkflowCipher Encrypt`: marks where public inputs enter the private subgraph
- `XLJworkflowCipher Bridge`: marks where private outputs leave the private subgraph
- `XLJworkflowCipher Decrypt`: shell node in the exported workflow
- `XLJworkflowCipher Random Seed`: utility node that generates a random integer seed

## Usage

### Selection-based vault mode

1. Build your workflow normally.
2. Select the nodes you want to hide.
3. Right-click and choose `Encrypt Selection`.
4. Enter a passphrase.
5. The selected nodes are replaced by a single vault node.
6. Share or run the resulting workflow.

To visually restore the hidden nodes, enter the original passphrase in the `password` field and run again.

### Flow-based mode

1. Place `XLJworkflowCipher Encrypt` before the private part of your graph.
2. Feed public upstream values into `input_1` to `input_16`.
3. Place `XLJworkflowCipher Bridge` after the private part of your graph.
4. Feed private outputs into `value_1` to `value_16`.
5. Connect bridge outputs to the public downstream graph.
6. Run the encrypt node once to export the shell workflow JSON.
7. Import the generated JSON into ComfyUI.

## Remote Backend

The plugin supports a remote backend for creator login, workflow registration, and key validation.

Default config shipped with the plugin:

```env
XLJWORKFLOWCIPHER_API_BASE=https://cf.xinlingjunai.net
XLJWORKFLOWCIPHER_PROXY_API_BASE=http://120.24.24.153:8218
XLJWORKFLOWCIPHER_PORTAL_URL=https://cf.xinlingjunai.net/xljworkflowcipher/portal
```

You can override these values by editing `service.env`.

Creator portal:

- `https://cf.xinlingjunai.net/xljworkflowcipher/portal`

## Notes

- The encrypted payload is stored in the workflow JSON inside node `properties`.
- Selection encryption supports optional key mode. When enabled, the vault stores a workflow key-group code and requires a valid `access_key` at runtime.
- Exactly one Encrypt node and one Bridge node are supported in flow-based mode.
- The vault node supports up to 16 public inputs and 16 public outputs.
- Hidden nodes are absent from the exported workflow JSON. Only the encrypted payload remains.
- The runtime passphrase mechanism is practical for workflow protection, but this is not a formally audited cryptographic product.

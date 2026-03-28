# ComfyUI-XLJworkflowCipher

Local workflow encryption nodes for ComfyUI. Lets you hide private nodes and model parameters from end users while still letting them run the workflow normally — no password required to execute.

This plugin is inspired by the graph-shell pattern used by `RiceRound/ComfyUI_CryptoCat`, but implemented as a fully offline packer:

- no external auth service
- no remote template upload
- no serial number issuance
- encrypted subgraph is embedded directly into the exported shell workflow
- decryption and execution happen locally and automatically at runtime

---

## Design philosophy

> **Anyone can run the workflow. Nobody can see what's inside.**

The password is only used to visually restore (unlock) the hidden nodes in the editor. At runtime, the vault decrypts and executes automatically — the `password` box can be left blank.

This is useful when you want to:
- share a workflow without revealing your node structure or model choices
- distribute a finished pipeline without exposing proprietary parameters
- protect prompt engineering or LoRA configurations from inspection

The encryption uses PBKDF2-HMAC-SHA256 with integrity verification. It is practical for local workflow protection, but is not a formally audited cryptographic product.

---

## Nodes

### ComfyUI-XLJworkflowCipher (selection-based, recommended)

Encrypts a selected group of nodes directly in the current workflow using right-click → "Encrypt Selection". Produces a self-contained vault node that runs without any password input.

**Inputs:** up to 16 public inputs routed into the hidden subgraph
**Outputs:** up to 16 outputs from the hidden subgraph back to the public graph
**password:** leave blank to run normally; enter the original passphrase to visually restore the hidden nodes

### XLJworkflowCipher Encrypt + Bridge + Decrypt (flow-based)

A three-node flow for more explicit control.

| Node | Purpose |
|---|---|
| `XLJworkflowCipher Encrypt` | Marks the boundary where public inputs enter the private subgraph. Run this node once to export the encrypted shell workflow. |
| `XLJworkflowCipher Bridge` | Marks the boundary where private outputs leave the private subgraph. |
| `XLJworkflowCipher Decrypt` | Shell node in the exported workflow. Decrypts and expands the hidden subgraph at runtime. |
| `XLJworkflowCipher Random Seed` | Utility node that generates a random integer seed each run. |

---

## Usage — Vault (selection-based)

1. Build your workflow normally.
2. Select the nodes you want to hide (the private subgraph).
3. Right-click → **Encrypt Selection** → enter a passphrase.
4. The selected nodes are replaced by a single **ComfyUI-XLJworkflowCipher** shell node.
5. Share or run the resulting workflow. The `password` box can be left empty — execution is automatic.
6. To restore the hidden nodes visually, enter the original passphrase in the `password` box and run.

## Usage — Encrypt/Bridge/Decrypt (flow-based)

1. Place `XLJworkflowCipher Encrypt` before the private part of your graph.
2. Feed public upstream values into `input_1` … `input_16`.
3. Place `XLJworkflowCipher Bridge` after the private part of your graph.
4. Feed private outputs into `value_1` … `value_16`.
5. Connect the bridge outputs to the public downstream part of the graph.
6. Run the encrypt node once — a shell workflow JSON is written to the ComfyUI output directory.
7. Import the generated JSON into ComfyUI.
8. The shell workflow runs automatically. Enter the passphrase in `XLJworkflowCipher Decrypt` only if you want to visually inspect or restore the hidden nodes.

---

## Notes

- The encrypted payload is embedded in the node's `properties` field inside the workflow JSON. The runtime passphrase is also stored there as `workflowcipher_runtime_key`, which is what enables passwordless execution.
- Exactly one Encrypt node and one Bridge node are supported per flow-based workflow.
- The vault node supports up to 16 public inputs and 16 public outputs.
- Hidden nodes are completely absent from the exported workflow JSON — only the encrypted binary payload is present.
- Future extension point: replace `workflowcipher_runtime_key` with a server-side key fetch for stricter access control.

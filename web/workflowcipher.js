import { app } from "/scripts/app.js";
import { api } from "/scripts/api.js";
import { GroupNodeHandler } from "/extensions/core/groupNode.js";

const VAULT_NODE_TYPE = "WorkflowCipherVaultNode";
const GROUP_NODE_PREFIX = "workflow/";
const HIDDEN_WIDGET_TYPE = "converted-widget:workflowcipher";
const BRAND_NAME = "XLJworkflowCipher";
const VAULT_TITLE = "ComfyUI-XLJworkflowCipher";
const ENCRYPT_SINGLE_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6b64\u8282\u70b9`;
const ENCRYPT_MULTI_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6240\u9009\u8282\u70b9`;
const RESTORE_LABEL = `${BRAND_NAME} \u8f93\u5165\u5bc6\u7801\u5e76\u8fd8\u539f`;

function getSelectedNodes(canvas) {
  const selected = canvas?.selected_nodes;
  if (!selected) {
    return [];
  }
  if (Array.isArray(selected)) {
    return selected.filter(Boolean);
  }
  return Object.values(selected).filter(Boolean);
}

function buildNodeTitle(_nodes) {
  return VAULT_TITLE;
}

function getNodeType(node) {
  return node?.comfyClass || node?.type || "";
}

function getWorkflowSnapshot() {
  if (typeof app.graph?.serialize === "function") {
    return structuredClone(app.graph.serialize());
  }
  return null;
}

function isVaultNode(node) {
  const nodeType = getNodeType(node);
  return nodeType === VAULT_NODE_TYPE || nodeType === VAULT_TITLE;
}

function isLockedGroupNode(node) {
  return Boolean(node?.properties?.workflowcipher_locked) && getNodeType(node).startsWith(GROUP_NODE_PREFIX);
}

function isWorkflowCipherControlNode(node) {
  return isVaultNode(node) || isLockedGroupNode(node);
}

function getPasswordWidget(node) {
  return node?.widgets?.find((widget) => widget?.name === "password") || null;
}

function getGroupHandler(node) {
  return Object.getOwnPropertySymbols(node || {})
    .map((symbol) => node[symbol])
    .find((value) => value instanceof GroupNodeHandler);
}

function hideWidget(widget) {
  if (!widget || widget.name === "password" || widget.type === HIDDEN_WIDGET_TYPE) {
    return;
  }
  if (!widget.origType) {
    widget.origType = widget.type;
  }
  if (!widget.origComputeSize) {
    widget.origComputeSize = widget.computeSize;
  }
  widget.computeSize = () => [0, -4];
  widget.type = HIDDEN_WIDGET_TYPE;
  for (const linkedWidget of widget.linkedWidgets || []) {
    hideWidget(linkedWidget);
  }
}

async function hashPassphrase(passphrase) {
  const text = new TextEncoder().encode(passphrase);
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", text);
    return Array.from(new Uint8Array(digest))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
  }
  return btoa(String.fromCharCode(...text));
}

function setNodeProperty(node, key, value) {
  if (typeof node.setProperty === "function") {
    node.setProperty(key, value);
  } else {
    node.properties = node.properties || {};
    node.properties[key] = value;
  }
}

function selectNode(node) {
  if (!node) {
    return;
  }
  if (typeof app.canvas.selectNode === "function") {
    app.canvas.selectNode(node);
  } else {
    node.selected = true;
  }
  app.canvas.setDirty?.(true, true);
}

function trimVaultPorts(node) {
  const inputCount = Math.max(0, Number(node.properties?.workflowcipher_input_count || node.inputs?.length || 0));
  const outputCount = Math.max(0, Number(node.properties?.workflowcipher_output_count || node.outputs?.length || 0));
  if (Array.isArray(node.inputs) && inputCount && node.inputs.length !== inputCount) {
    node.inputs = node.inputs.slice(0, inputCount);
  }
  if (Array.isArray(node.outputs) && outputCount && node.outputs.length !== outputCount) {
    node.outputs = node.outputs.slice(0, outputCount);
  }
}

function applyCipherAppearance(node) {
  if (!node || node.__workflowCipherAppearanceApplied) {
    return;
  }
  node.__workflowCipherAppearanceApplied = true;

  if (isVaultNode(node)) {
    trimVaultPorts(node);
  }

  if (isLockedGroupNode(node)) {
    for (const widget of node.widgets || []) {
      if (widget.name !== "password") {
        hideWidget(widget);
      }
    }
  }

  // Hide all individual port labels
  for (const input of node.inputs || []) {
    input.label = " ";
  }
  for (const output of node.outputs || []) {
    output.label = " ";
  }

  // Dark encrypted appearance
  node.color = "#1a1a2e";
  node.bgcolor = "#16213e";

  const nodeWidth = 320;
  const nodeHeight = 160;

  node.serialize_widgets = true;
  node.computeSize = () => [nodeWidth, nodeHeight];

  // ── Single-dot ports ──────────────────────────────────────────────────────
  // Override getConnectionPos so every input slot maps to one left dot
  // and every output slot maps to one right dot.
  // LiteGraph calls this with (is_input, slot_index, out_vec2).
  node.getConnectionPos = function (is_input, _slot, out) {
    const res = out || new Float32Array(2);
    const cy = this.size[1] / 2;
    res[0] = is_input ? 0 : this.size[0];
    res[1] = cy;
    return res;
  };

  // Draw the two visible dots + lock watermark ourselves
  const originalDrawForeground = node.onDrawForeground;
  node.onDrawForeground = function (ctx) {
    originalDrawForeground?.apply(this, arguments);

    const w = this.size[0];
    const h = this.size[1];
    const cy = h / 2;
    const DOT_R = 6;
    const DOT_COLOR = "#7ecfff";

    ctx.save();

    // Left input dot
    if ((this.inputs || []).length > 0) {
      ctx.beginPath();
      ctx.arc(0, cy, DOT_R, 0, Math.PI * 2);
      ctx.fillStyle = DOT_COLOR;
      ctx.fill();
      ctx.strokeStyle = "#ffffff44";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Right output dot
    if ((this.outputs || []).length > 0) {
      ctx.beginPath();
      ctx.arc(w, cy, DOT_R, 0, Math.PI * 2);
      ctx.fillStyle = DOT_COLOR;
      ctx.fill();
      ctx.strokeStyle = "#ffffff44";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Lock watermark
    const centerX = w / 2;
    const lockY = h * 0.35;
    ctx.globalAlpha = 0.08;
    ctx.fillStyle = "#ffffff";
    ctx.beginPath();
    ctx.roundRect(centerX - 20, lockY, 40, 30, 4);
    ctx.fill();
    ctx.globalAlpha = 0.12;
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 4;
    ctx.lineCap = "round";
    ctx.beginPath();
    ctx.arc(centerX, lockY, 13, Math.PI, 0);
    ctx.stroke();

    ctx.restore();
  };
  // ─────────────────────────────────────────────────────────────────────────

  if (typeof node.setSize === "function") {
    node.setSize([nodeWidth, nodeHeight]);
  } else {
    node.size = [nodeWidth, nodeHeight];
  }
  node.setDirtyCanvas?.(true, true);
}

async function verifyPassphrase(node, passphrase) {
  const expectedHash = node?.properties?.workflowcipher_passphrase_hash;
  if (!expectedHash) {
    return false;
  }
  return (await hashPassphrase(passphrase)) === expectedHash;
}

async function encryptSelectionToVault(selectedNodes, passphrase) {
  const promptData = structuredClone(await app.graphToPrompt());
  const workflowData = getWorkflowSnapshot() || promptData.workflow;
  const response = await api.fetchApi("/xljworkflowcipher/encrypt_selection", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      workflow: workflowData,
      prompt: promptData.output,
      selected_node_ids: selectedNodes.map((node) => node.id),
      passphrase,
      node_title: buildNodeTitle(selectedNodes),
    }),
  });

  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(data.error || `${BRAND_NAME} request failed: ${response.status}`);
  }

  app.graph?.clear?.();
  await app.loadGraphData(data.workflow);
  requestAnimationFrame(() => {
    const shellNode = app.graph.getNodeById?.(data.shell_node_id);
    if (!shellNode) {
      return;
    }
    applyCipherAppearance(shellNode);
    installPasswordHandler(shellNode);
    selectNode(shellNode);
  });
}

async function restoreVaultNode(node, passphrase) {
  if (!node || !passphrase) {
    return;
  }

  const workflowData = getWorkflowSnapshot() || structuredClone((await app.graphToPrompt()).workflow);
  const response = await api.fetchApi("/xljworkflowcipher/decrypt_selection", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      workflow: workflowData,
      shell_node_id: node.id,
      passphrase,
    }),
  });

  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(data.error || `${BRAND_NAME} request failed: ${response.status}`);
  }

  app.graph?.clear?.();
  await app.loadGraphData(data.workflow);
  requestAnimationFrame(() => {
    const restoredIds = new Set(data.restored_node_ids || []);
    for (const graphNode of app.graph._nodes || []) {
      graphNode.selected = restoredIds.has(graphNode.id);
    }
    app.canvas.setDirty?.(true, true);
  });
}

async function restoreLockedGroupNode(node, passphrase) {
  if (!(await verifyPassphrase(node, passphrase))) {
    throw new Error("\u5bc6\u7801\u4e0d\u6b63\u786e");
  }
  const restoredNodes = node.convertToNodes?.();
  if (Array.isArray(restoredNodes)) {
    for (const restoredNode of restoredNodes) {
      restoredNode.selected = true;
    }
  }
  app.graph.setDirtyCanvas?.(true, true);
}

async function lockGroupNode(node, passphrase, title) {
  setNodeProperty(node, "workflowcipher_locked", true);
  setNodeProperty(node, "workflowcipher_passphrase_hash", await hashPassphrase(passphrase));
  setNodeProperty(node, "workflowcipher_title", title);
  node.title = title;
  applyCipherAppearance(node);
  installPasswordHandler(node);
  selectNode(node);
}

async function encryptSelection(nodes) {
  // If multiple nodes are selected on canvas, always use all of them
  const canvasSelected = getSelectedNodes(app.canvas).filter((n) => !isWorkflowCipherControlNode(n));
  const selectedNodes = canvasSelected.length > 1 ? canvasSelected : (nodes?.length ? nodes : canvasSelected);
  if (!selectedNodes.length) {
    window.alert("\u8bf7\u5148\u9009\u62e9\u8981\u52a0\u5bc6\u7684\u8282\u70b9\u3002");
    return;
  }

  const passphrase = window.prompt(`\u8bf7\u8f93\u5165 ${BRAND_NAME} \u5bc6\u7801`);
  if (!passphrase) {
    return;
  }

  await encryptSelectionToVault(selectedNodes, passphrase);
}

async function handlePasswordCommit(node, passphrase) {
  if (!passphrase) {
    return;
  }
  if (isLockedGroupNode(node)) {
    await restoreLockedGroupNode(node, passphrase);
    return;
  }
  if (isVaultNode(node)) {
    await restoreVaultNode(node, passphrase);
  }
}

function installPasswordHandler(node) {
  if (!node) {
    return;
  }

  if (isLockedGroupNode(node) && !getPasswordWidget(node)) {
    const widget = node.addWidget("text", "password", "", async function () {
      const value = this.value;
      if (!value || node.__workflowCipherRestoring) {
        return value;
      }
      node.__workflowCipherRestoring = true;
      try {
        await handlePasswordCommit(node, value);
      } catch (error) {
        window.alert(`${BRAND_NAME} \u89e3\u5c01\u5931\u8d25: ${error.message}`);
      } finally {
        node.__workflowCipherRestoring = false;
        this.value = "";
      }
      return value;
    });
    widget.options = { ...(widget.options || {}), multiline: false };
  }

  const widget = getPasswordWidget(node);
  if (!widget || widget.__workflowCipherPasswordWrapped) {
    return;
  }

  widget.__workflowCipherPasswordWrapped = true;
  const originalCallback = widget.callback;
  widget.callback = async function () {
    const value = (await originalCallback?.apply(this, arguments)) ?? this.value;
    if (!value || node.__workflowCipherRestoring) {
      return value;
    }
    node.__workflowCipherRestoring = true;
    try {
      await handlePasswordCommit(node, value);
    } catch (error) {
      window.alert(`${BRAND_NAME} \u89e3\u5c01\u5931\u8d25: ${error.message}`);
    } finally {
      node.__workflowCipherRestoring = false;
      this.value = "";
    }
    return value;
  };
}

function addEncryptMenu(node, options) {
  if (isWorkflowCipherControlNode(node)) {
    return;
  }
  options.push(null);
  options.push({
    content: ENCRYPT_SINGLE_LABEL,
    callback: () =>
      encryptSelection([node]).catch((error) => {
        window.alert(`${BRAND_NAME} \u52a0\u5bc6\u5931\u8d25: ${error.message}`);
      }),
  });
}

function addRestoreMenu(node, options) {
  if (!isLockedGroupNode(node) && !isVaultNode(node)) {
    return;
  }
  options.push(null);
  options.push({
    content: RESTORE_LABEL,
    callback: () => {
      const password =
        getPasswordWidget(node)?.value || window.prompt("\u8bf7\u8f93\u5165\u5bc6\u7801");
      if (!password) {
        return;
      }
      handlePasswordCommit(node, password).catch((error) => {
        window.alert(`${BRAND_NAME} \u89e3\u5c01\u5931\u8d25: ${error.message}`);
      });
    },
  });
}

function injectCanvasContextMenu() {
  if (LGraphCanvas.prototype.__workflowCipherCanvasMenuWrapped) {
    return;
  }
  LGraphCanvas.prototype.__workflowCipherCanvasMenuWrapped = true;

  const original = LGraphCanvas.prototype.getCanvasMenuOptions;
  LGraphCanvas.prototype.getCanvasMenuOptions = function () {
    const options = original ? original.apply(this, arguments) : [];
    const selectedNodes = getSelectedNodes(this).filter((node) => !isWorkflowCipherControlNode(node));
    if (selectedNodes.length) {
      options.push(null);
      options.push({
        content: ENCRYPT_MULTI_LABEL,
        callback: () =>
          encryptSelection(selectedNodes).catch((error) => {
            window.alert(`${BRAND_NAME} \u52a0\u5bc6\u5931\u8d25: ${error.message}`);
          }),
      });
    }
    return options;
  };
}

function patchVaultNodeType(nodeType) {
  if (nodeType.prototype.__workflowCipherVaultPatched) {
    return;
  }
  nodeType.prototype.__workflowCipherVaultPatched = true;

  const originalOnAdded = nodeType.prototype.onAdded;
  nodeType.prototype.onAdded = function () {
    const result = originalOnAdded?.apply(this, arguments);
    applyCipherAppearance(this);
    installPasswordHandler(this);
    return result;
  };

  const originalConfigure = nodeType.prototype.configure;
  nodeType.prototype.configure = function () {
    const result = originalConfigure?.apply(this, arguments);
    // Reset flag so the deferred call can re-apply (ComfyUI may add optional slots after configure)
    this.__workflowCipherAppearanceApplied = false;
    // Defer so ComfyUI finishes adding optional slots before we trim
    requestAnimationFrame(() => {
      applyCipherAppearance(this);
      installPasswordHandler(this);
    });
    return result;
  };
}

app.registerExtension({
  name: "ComfyUI.XLJworkflowCipher",
  async beforeRegisterNodeDef(nodeType, nodeData) {
    if (nodeData?.name === VAULT_NODE_TYPE) {
      patchVaultNodeType(nodeType);
    }

    if (nodeType.prototype.__workflowCipherNodeMenuWrapped) {
      return;
    }
    nodeType.prototype.__workflowCipherNodeMenuWrapped = true;

    const original = nodeType.prototype.getExtraMenuOptions;
    nodeType.prototype.getExtraMenuOptions = function (_, options) {
      original?.apply(this, arguments);
      addRestoreMenu(this, options);
      addEncryptMenu(this, options);
    };
  },
  nodeCreated(node) {
    if (!isLockedGroupNode(node) && !isVaultNode(node)) {
      return;
    }
    applyCipherAppearance(node);
    installPasswordHandler(node);
  },
  setup() {
    injectCanvasContextMenu();
  },
});

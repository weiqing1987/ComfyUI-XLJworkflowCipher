import { app } from "/scripts/app.js";
import { api } from "/scripts/api.js";
import { GroupNodeHandler } from "/extensions/core/groupNode.js";

const VAULT_NODE_TYPE = "WorkflowCipherVaultNode";
const GROUP_NODE_PREFIX = "workflow/";
const HIDDEN_WIDGET_TYPE = "converted-widget:workflowcipher";
const BRAND_NAME = "XLJworkflowCipher";
const VAULT_TITLE = "ComfyUI-XLJworkflowCipher";
const ACCESS_KEY_WIDGET = "access_key";
const ENCRYPT_SINGLE_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6b64\u8282\u70b9`;
const ENCRYPT_MULTI_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6240\u9009\u8282\u70b9`;
const RESTORE_LABEL = `${BRAND_NAME} \u8f93\u5165\u5bc6\u7801\u5e76\u8fd8\u539f`;
const PORTAL_LABEL = `${BRAND_NAME} \u5bc6\u94a5\u7ba1\u7406\u9875`;

// Remember key settings after decryption for auto-fill on re-encrypt
let rememberedKeySettings = null;

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

function getWidget(node, name) {
  return node?.widgets?.find((widget) => widget?.name === name) || null;
}

function getPasswordWidget(node) {
  return getWidget(node, "password");
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

function showWidget(widget) {
  if (!widget) {
    return;
  }
  if (widget.origComputeSize) {
    widget.computeSize = widget.origComputeSize;
  }
  if (widget.origType) {
    widget.type = widget.origType;
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

function getVisibleWidgetNames(node) {
  const names = new Set(["password"]);
  if (node?.properties?.workflowcipher_key_required) {
    names.add(ACCESS_KEY_WIDGET);
  }
  return names;
}

async function requestJson(url, options = {}) {
  const response = await api.fetchApi(url, options);
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(data.error || `${BRAND_NAME} request failed: ${response.status}`);
  }
  return data;
}

function openPortalPage() {
  window.open("/xljworkflowcipher/portal", "_blank", "noopener,noreferrer");
}

function promptEncryptionOptions() {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.style.cssText = [
      "position:fixed",
      "inset:0",
      "background:rgba(5,9,18,0.72)",
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "z-index:99999",
      "padding:20px",
    ].join(";");

    const panel = document.createElement("form");
    panel.style.cssText = [
      "width:min(420px,100%)",
      "background:#131a2a",
      "border:1px solid rgba(255,255,255,0.08)",
      "border-radius:22px",
      "padding:22px",
      "color:#eef3ff",
      "box-shadow:0 30px 80px rgba(0,0,0,0.45)",
      "display:grid",
      "gap:14px",
    ].join(";");

    panel.innerHTML = `
      <div>
        <div style="font-size:13px;color:#71d9cb;letter-spacing:0.12em;text-transform:uppercase;">${BRAND_NAME}</div>
        <h3 style="margin:8px 0 0;font-size:24px;">加密设置</h3>
        <p style="margin:10px 0 0;color:#9fb0d0;line-height:1.6;">
          关闭密钥开关时保持当前行为。开启后，工作流运行必须输入对应密钥。
        </p>
      </div>
      <label style="display:grid;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">密码</span>
        <input name="passphrase" type="password" autocomplete="new-password" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,0.04);">
        <input name="key_required" type="checkbox" style="inline-size:18px;block-size:18px;" />
        <span>启用密钥</span>
      </label>
      <label data-key-row style="display:none;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">加密组编号 / 名称</span>
        <input name="key_group" placeholder="例如: grok_video_pro" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
      </label>
      <div style="display:flex;gap:12px;justify-content:flex-end;">
        <button type="button" data-action="portal" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">密钥管理页</button>
        <button type="button" data-action="cancel" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">取消</button>
        <button type="submit" style="padding:11px 16px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#4ec7b9;color:#082420;font-weight:700;">确认加密</button>
      </div>
    `;

    const passphraseInput = panel.querySelector('input[name="passphrase"]');
    const keyRequiredInput = panel.querySelector('input[name="key_required"]');
    const keyGroupInput = panel.querySelector('input[name="key_group"]');
    const keyRow = panel.querySelector("[data-key-row]");

    // Auto-fill remembered key settings from previous decryption
    if (rememberedKeySettings) {
      keyRequiredInput.checked = rememberedKeySettings.keyRequired;
      keyGroupInput.value = rememberedKeySettings.keyGroup || "";
    }

    function cleanup(value) {
      overlay.remove();
      resolve(value);
    }

    function syncKeyRow() {
      keyRow.style.display = keyRequiredInput.checked ? "grid" : "none";
    }

    // Sync initial state (show key_group input if remembered)
    syncKeyRow();

    keyRequiredInput.addEventListener("change", syncKeyRow);
    panel.querySelector('[data-action="cancel"]').addEventListener("click", () => cleanup(null));
    panel.querySelector('[data-action="portal"]').addEventListener("click", () => openPortalPage());
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        cleanup(null);
      }
    });

    panel.addEventListener("submit", (event) => {
      event.preventDefault();
      const passphrase = passphraseInput.value?.trim();
      const keyRequired = Boolean(keyRequiredInput.checked);
      const keyGroup = keyGroupInput.value?.trim();

      if (!passphrase) {
        window.alert("\u8bf7\u5148\u8f93\u5165\u5bc6\u7801\u3002");
        return;
      }
      if (keyRequired && !keyGroup) {
        window.alert("\u5f00\u542f\u5bc6\u94a5\u540e\uff0c\u5fc5\u987b\u586b\u5199\u52a0\u5bc6\u7ec4\u7f16\u53f7\u6216\u540d\u79f0\u3002");
        return;
      }

      cleanup({
        passphrase,
        keyRequired,
        keyGroup: keyRequired ? keyGroup : "",
      });
    });

    overlay.appendChild(panel);
    document.body.appendChild(overlay);
    passphraseInput.focus();
  });
}

function applyCipherAppearance(node) {
  if (!node || node.__workflowCipherAppearanceApplied) {
    return;
  }
  node.__workflowCipherAppearanceApplied = true;

  if (isVaultNode(node)) {
    trimVaultPorts(node);
  }

  const visibleWidgetNames = getVisibleWidgetNames(node);
  for (const widget of node.widgets || []) {
    if (visibleWidgetNames.has(widget.name)) {
      showWidget(widget);
    } else {
      hideWidget(widget);
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
  const nodeHeight = node?.properties?.workflowcipher_key_required ? 198 : 160;

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

async function encryptSelectionToVault(selectedNodes, options) {
  const promptData = structuredClone(await app.graphToPrompt());
  const workflowData = getWorkflowSnapshot() || promptData.workflow;
  const data = await requestJson("/xljworkflowcipher/encrypt_selection", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      workflow: workflowData,
      prompt: promptData.output,
      selected_node_ids: selectedNodes.map((node) => node.id),
      passphrase: options.passphrase,
      node_title: buildNodeTitle(selectedNodes),
      key_required: options.keyRequired,
      key_group: options.keyGroup,
    }),
  });

  // Clear remembered settings after successful encryption
  rememberedKeySettings = null;

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
  if (!node) {
    return;
  }

  const workflowData = getWorkflowSnapshot() || structuredClone((await app.graphToPrompt()).workflow);
  const data = await requestJson("/xljworkflowcipher/decrypt_selection", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      workflow: workflowData,
      shell_node_id: node.id,
      passphrase,
    }),
  });

  // Remember key settings for auto-fill on re-encrypt
  if (data.remembered_key_group) {
    rememberedKeySettings = {
      keyRequired: data.remembered_key_required,
      keyGroup: data.remembered_key_group,
    };
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

  const options = await promptEncryptionOptions();
  if (!options) {
    return;
  }

  await encryptSelectionToVault(selectedNodes, options);
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

async function maybeRestoreDestroyedVault(node) {
  if (!isVaultNode(node) || !node?.properties?.workflowcipher_key_required) {
    return;
  }
  if (node.__workflowCipherDestroyCheckStarted) {
    return;
  }
  const keyGroup = (node?.properties?.workflowcipher_key_group || "").trim();
  if (!keyGroup) {
    return;
  }

  node.__workflowCipherDestroyCheckStarted = true;
  try {
    const status = await requestJson(`/xljworkflowcipher/api/key-groups/status?code=${encodeURIComponent(keyGroup)}`);
    if (status?.destroyed) {
      await restoreVaultNode(node, "");
    }
  } catch (_error) {
    // Keep the node usable even if the management service is unavailable.
  } finally {
    node.__workflowCipherDestroyCheckStarted = false;
  }
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
    options.push({
      content: PORTAL_LABEL,
      callback: () => openPortalPage(),
    });
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
      maybeRestoreDestroyedVault(this);
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
    maybeRestoreDestroyedVault(node);
  },
  setup() {
    injectCanvasContextMenu();
  },
});

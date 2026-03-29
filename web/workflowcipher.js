import { app } from "/scripts/app.js";
import { api } from "/scripts/api.js";
import { GroupNodeHandler } from "/extensions/core/groupNode.js";

const VAULT_NODE_TYPE = "WorkflowCipherVaultNode";
const GROUP_NODE_PREFIX = "workflow/";
const HIDDEN_WIDGET_TYPE = "converted-widget:workflowcipher";
const BRAND_NAME = "XLJworkflowCipher";
const VAULT_TITLE = "ComfyUI-XLJworkflowCipher";
const ACCESS_KEY_WIDGET = "access_key";
const PASSWORD_WIDGET_NAME = "password";
const PASSWORD_DISPLAY_LABEL = "\u5f00\u653e\u8282\u70b9\uff08\u89e3\u5bc6\u8282\u70b9\uff09";
const ACCESS_KEY_DISPLAY_LABEL = "\u5bc6\u94a5";
const RESTORE_BUTTON_LABEL = "\u5f00\u653e\u8282\u70b9";
const ENCRYPT_SINGLE_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6b64\u8282\u70b9`;
const ENCRYPT_MULTI_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6240\u9009\u8282\u70b9`;
const RESTORE_LABEL = `${BRAND_NAME} \u8f93\u5165\u5bc6\u7801\u5e76\u8fd8\u539f`;
const PORTAL_LABEL = `${BRAND_NAME} \u4e2a\u4eba\u4e2d\u5fc3`;
const PORTAL_BUTTON_LABEL = "\u4e2a\u4eba\u4e2d\u5fc3";
const DEFAULT_PORTAL_URL = "/xljworkflowcipher/portal";
const DEFAULT_FRONTEND_CONFIG = Object.freeze({
  api_base: "",
  portal_url: DEFAULT_PORTAL_URL,
  remote_enabled: false,
});

let workflowCipherFrontendConfig = { ...DEFAULT_FRONTEND_CONFIG };
let workflowCipherFrontendConfigPromise = null;
let workflowCipherPortalSession = { user: null, groups: [] };
let workflowCipherPortalSessionPromise = null;

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
  if (getAccessKeyWidget(node)) {
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

function normalizeFrontendConfig(config) {
  const apiBase = typeof config?.api_base === "string" ? config.api_base.trim() : "";
  const portalUrl =
    typeof config?.portal_url === "string" && config.portal_url.trim()
      ? config.portal_url.trim()
      : DEFAULT_FRONTEND_CONFIG.portal_url;
  return {
    api_base: apiBase,
    portal_url: portalUrl,
    remote_enabled: Boolean(config?.remote_enabled || apiBase),
  };
}

function getPortalUrl() {
  return workflowCipherFrontendConfig.portal_url || DEFAULT_FRONTEND_CONFIG.portal_url;
}

function loadFrontendConfig(force = false) {
  if (!force && workflowCipherFrontendConfigPromise) {
    return workflowCipherFrontendConfigPromise;
  }

  workflowCipherFrontendConfigPromise = requestJson("/xljworkflowcipher/api/frontend-config")
    .then((config) => {
      workflowCipherFrontendConfig = normalizeFrontendConfig(config);
      return workflowCipherFrontendConfig;
    })
    .catch((error) => {
      workflowCipherFrontendConfigPromise = null;
      throw error;
    });

  return workflowCipherFrontendConfigPromise;
}

function openPortalPage() {
  window.open(getPortalUrl(), "_blank", "noopener,noreferrer");
}

void loadFrontendConfig().catch(() => null);

function setPortalSession(payload = {}) {
  workflowCipherPortalSession = {
    user: payload.user || null,
    groups: Array.isArray(payload.groups) ? payload.groups : [],
  };
  return workflowCipherPortalSession;
}

function clearPortalSession() {
  return setPortalSession();
}

function loadPortalSession(force = false) {
  if (!force && workflowCipherPortalSessionPromise) {
    return workflowCipherPortalSessionPromise;
  }

  workflowCipherPortalSessionPromise = requestJson("/xljworkflowcipher/api/me")
    .then((payload) => {
      setPortalSession(payload);
      return workflowCipherPortalSession;
    })
    .catch((error) => {
      workflowCipherPortalSessionPromise = null;
      clearPortalSession();
      throw error;
    });

  return workflowCipherPortalSessionPromise;
}

async function loadPortalSessionSafe(force = false) {
  try {
    return await loadPortalSession(force);
  } catch (_error) {
    return clearPortalSession();
  }
}

async function loginPortalSession(username, password) {
  const payload = await requestJson("/xljworkflowcipher/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: (username || "").trim(),
      password: password || "",
    }),
  });
  setPortalSession(payload);
  workflowCipherPortalSessionPromise = Promise.resolve(workflowCipherPortalSession);
  return workflowCipherPortalSession;
}

async function upsertPortalWorkflow(identifier) {
  const value = (identifier || "").trim();
  if (!value) {
    throw new Error("\u8bf7\u8f93\u5165\u5de5\u4f5c\u6d41 ID / \u4ee3\u53f7 / \u540d\u79f0\u3002");
  }
  const payload = await requestJson("/xljworkflowcipher/api/workflows", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: value,
      name: value,
    }),
  });
  await loadPortalSessionSafe(true);
  return payload.group;
}

void loadPortalSessionSafe().catch(() => null);

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

    function cleanup(value) {
      overlay.remove();
      resolve(value);
    }

    function syncKeyRow() {
      keyRow.style.display = keyRequiredInput.checked ? "grid" : "none";
    }

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

function getAccessKeyWidget(node) {
  return getWidget(node, ACCESS_KEY_WIDGET);
}

function setWorkflowCipherWidgetLabel(widget, label) {
  if (!widget) {
    return;
  }
  widget.label = label;
  widget.options = {
    ...(widget.options || {}),
    label,
  };
}

async function requestNodeRestore(node) {
  if (!node || node.__workflowCipherRestoring) {
    return;
  }

  const passwordWidget = getPasswordWidget(node);
  const passphrase =
    passwordWidget?.value?.trim() ||
    window.prompt("\u8bf7\u8f93\u5165\u5f00\u653e\u8282\u70b9\uff08\u89e3\u5bc6\u8282\u70b9\uff09")?.trim();
  if (!passphrase) {
    return;
  }

  node.__workflowCipherRestoring = true;
  try {
    await handlePasswordCommit(node, passphrase);
  } catch (error) {
    window.alert(`${BRAND_NAME} \u89e3\u5c01\u5931\u8d25: ${error.message}`);
  } finally {
    node.__workflowCipherRestoring = false;
    if (passwordWidget) {
      passwordWidget.value = "";
    }
  }
}

function ensureRestoreButton(node) {
  if (!node || getWidget(node, RESTORE_BUTTON_LABEL)) {
    return;
  }

  const widget = node.addWidget("button", RESTORE_BUTTON_LABEL, null, () => requestNodeRestore(node));
  widget.serialize = false;
}

getPasswordWidget = function (node) {
  return getWidget(node, PASSWORD_WIDGET_NAME);
};

getVisibleWidgetNames = function (node) {
  const names = new Set([PASSWORD_WIDGET_NAME]);
  if (getAccessKeyWidget(node)) {
    names.add(ACCESS_KEY_WIDGET);
  }
  return names;
};

promptEncryptionOptions = function () {
  return new Promise((resolve) => {
    const dialogState = {
      user: workflowCipherPortalSession.user,
      busy: false,
    };

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
      "width:min(460px,100%)",
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
        <h3 style="margin:8px 0 0;font-size:24px;">\u52a0\u5bc6\u8bbe\u7f6e</h3>
        <p style="margin:10px 0 0;color:#9fb0d0;line-height:1.6;">
          \u4e24\u4e2a\u8868\u5355\u4f1a\u4e00\u76f4\u663e\u793a\uff1a\u7b2c\u4e00\u4e2a\u7528\u4e8e\u540e\u7eed\u6253\u5f00\u8282\u70b9\uff0c\u7b2c\u4e8c\u4e2a\u7528\u4e8e\u7ed1\u5b9a\u5bc6\u94a5\u3002
          \u4e0d\u542f\u7528\u5bc6\u94a5\u65f6\uff0c\u201c\u5bc6\u94a5\u201d\u53ef\u7559\u7a7a\u3002
        </p>
      </div>
      <label style="display:grid;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">${PASSWORD_DISPLAY_LABEL}</span>
        <input name="passphrase" type="password" autocomplete="new-password" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,0.04);">
        <input name="key_required" type="checkbox" style="inline-size:18px;block-size:18px;" />
        <span>\u542f\u7528\u5bc6\u94a5\u6821\u9a8c</span>
      </label>
      <div data-auth-wrap style="display:none;gap:10px;padding:14px;border-radius:16px;background:rgba(255,255,255,0.04);">
        <div data-auth-logged-in style="display:none;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <div style="font-size:14px;color:#eef3ff;">\u5df2\u767b\u5f55</div>
            <div data-user-text style="font-size:12px;color:#9fb0d0;"></div>
          </div>
          <button type="button" data-action="portal-inline" style="padding:9px 12px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">${PORTAL_BUTTON_LABEL}</button>
        </div>
        <div data-auth-form style="display:grid;gap:10px;">
          <label style="display:grid;gap:8px;">
            <span style="color:#9fb0d0;font-size:14px;">\u8d26\u53f7</span>
            <input name="portal_username" autocomplete="username" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
          </label>
          <label style="display:grid;gap:8px;">
            <span style="color:#9fb0d0;font-size:14px;">\u5bc6\u7801</span>
            <input name="portal_password" type="password" autocomplete="current-password" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
          </label>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button type="button" data-action="login" style="padding:10px 14px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);background:#4ec7b9;color:#082420;font-weight:700;">\u767b\u5f55\u5e76\u542f\u7528</button>
            <button type="button" data-action="register" style="padding:10px 14px;border-radius:12px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">\u6ca1\u6709\u8d26\u53f7\uff1f\u53bb\u6ce8\u518c</button>
          </div>
          <div data-auth-message style="min-height:18px;font-size:12px;color:#9fb0d0;"></div>
        </div>
      </div>
      <label data-key-row style="display:none;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">\u5de5\u4f5c\u6d41 ID / \u4ee3\u53f7 / \u540d\u79f0</span>
        <input name="key_group" placeholder="\u767b\u5f55\u540e\u586b\u5199" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
        <span data-key-hint style="color:#7082a6;font-size:12px;line-height:1.5;"></span>
      </label>
      <div style="display:flex;gap:12px;justify-content:flex-end;">
        <button type="button" data-action="portal" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">${PORTAL_BUTTON_LABEL}</button>
        <button type="button" data-action="cancel" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">\u53d6\u6d88</button>
        <button type="submit" style="padding:11px 16px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#4ec7b9;color:#082420;font-weight:700;">\u786e\u8ba4\u52a0\u5bc6</button>
      </div>
    `;

    const passphraseInput = panel.querySelector('input[name="passphrase"]');
    const keyRequiredInput = panel.querySelector('input[name="key_required"]');
    const keyGroupInput = panel.querySelector('input[name="key_group"]');
    const keyHint = panel.querySelector("[data-key-hint]");
    const authWrap = panel.querySelector("[data-auth-wrap]");
    const authForm = panel.querySelector("[data-auth-form]");
    const authLoggedIn = panel.querySelector("[data-auth-logged-in]");
    const userText = panel.querySelector("[data-user-text]");
    const authMessage = panel.querySelector("[data-auth-message]");
    const portalUsernameInput = panel.querySelector('input[name="portal_username"]');
    const portalPasswordInput = panel.querySelector('input[name="portal_password"]');
    const loginButton = panel.querySelector('[data-action="login"]');
    const submitButton = panel.querySelector('button[type="submit"]');
    const keyRow = panel.querySelector("[data-key-row]");

    function cleanup(value) {
      overlay.remove();
      resolve(value);
    }

    function setBusy(busy) {
      dialogState.busy = busy;
      submitButton.disabled = busy;
      loginButton.disabled = busy;
      keyRequiredInput.disabled = busy;
      portalUsernameInput.disabled = busy;
      portalPasswordInput.disabled = busy;
      keyGroupInput.disabled = busy || (keyRequiredInput.checked && !dialogState.user);
    }

    function setAuthMessage(message, isError = false) {
      authMessage.textContent = message || "";
      authMessage.style.color = isError ? "#ffb7c3" : "#9fb0d0";
    }

    function syncDialogState() {
      const keyRequired = Boolean(keyRequiredInput.checked);
      const loggedIn = Boolean(dialogState.user);
      authWrap.style.display = keyRequired ? "grid" : "none";
      authForm.style.display = keyRequired && !loggedIn ? "grid" : "none";
      authLoggedIn.style.display = keyRequired && loggedIn ? "flex" : "none";
      keyRow.style.display = keyRequired ? "grid" : "none";
      userText.textContent = loggedIn ? dialogState.user.username : "";
      keyGroupInput.disabled = dialogState.busy || (keyRequired && !loggedIn);
      keyGroupInput.placeholder = keyRequired
        ? loggedIn
          ? "\u4f8b\u5982: grok_video_pro"
          : "\u8bf7\u5148\u767b\u5f55"
        : "\u4e0d\u542f\u7528\u65f6\u53ef\u7559\u7a7a";
      if (!keyRequired) {
        keyHint.textContent = "\u4e0d\u542f\u7528\u5bc6\u94a5\u65f6\uff0c\u4f1a\u4fdd\u6301\u672c\u5730\u79bb\u7ebf\u52a0\u5bc6\u6a21\u5f0f\u3002";
      } else if (!loggedIn) {
        keyHint.textContent = "\u542f\u7528\u5bc6\u94a5\u540e\uff0c\u8bf7\u5148\u767b\u5f55\uff0c\u7136\u540e\u586b\u5199\u5de5\u4f5c\u6d41 ID / \u4ee3\u53f7 / \u540d\u79f0\u3002";
      } else {
        keyHint.textContent = "\u786e\u8ba4\u52a0\u5bc6\u65f6\uff0c\u8fd9\u4e2a ID / \u4ee3\u53f7 / \u540d\u79f0\u4f1a\u81ea\u52a8\u540c\u6b65\u5230\u4e2a\u4eba\u4e2d\u5fc3\u3002";
      }
    }

    async function refreshPortalSession(force = false) {
      const session = await loadPortalSessionSafe(force);
      dialogState.user = session.user;
      syncDialogState();
      return session;
    }

    keyRequiredInput.addEventListener("change", () => {
      syncDialogState();
      if (keyRequiredInput.checked && !dialogState.user) {
        void refreshPortalSession(true);
      }
    });
    panel.querySelector('[data-action="cancel"]').addEventListener("click", () => cleanup(null));
    panel.querySelector('[data-action="portal"]').addEventListener("click", () => openPortalPage());
    panel.querySelector('[data-action="portal-inline"]').addEventListener("click", () => openPortalPage());
    panel.querySelector('[data-action="register"]').addEventListener("click", () => openPortalPage());
    panel.querySelector('[data-action="login"]').addEventListener("click", async () => {
      const username = portalUsernameInput.value?.trim();
      const password = portalPasswordInput.value || "";
      if (!username || !password) {
        setAuthMessage("\u8bf7\u5148\u586b\u5199\u8d26\u53f7\u548c\u5bc6\u7801\u3002", true);
        return;
      }
      setBusy(true);
      setAuthMessage("\u6b63\u5728\u767b\u5f55...");
      try {
        const session = await loginPortalSession(username, password);
        dialogState.user = session.user;
        portalPasswordInput.value = "";
        setAuthMessage("\u767b\u5f55\u6210\u529f\uff0c\u73b0\u5728\u53ef\u4ee5\u542f\u7528\u5bc6\u94a5\u6821\u9a8c\u4e86\u3002");
      } catch (error) {
        setAuthMessage(error.message, true);
      } finally {
        setBusy(false);
        syncDialogState();
      }
    });
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        cleanup(null);
      }
    });

    panel.addEventListener("submit", async (event) => {
      event.preventDefault();
      const passphrase = passphraseInput.value?.trim();
      const keyRequired = Boolean(keyRequiredInput.checked);
      const keyGroup = keyGroupInput.value?.trim();

      if (!passphrase) {
        window.alert("\u8bf7\u5148\u586b\u5199\u5f00\u653e\u8282\u70b9\uff08\u89e3\u5bc6\u8282\u70b9\uff09\u3002");
        return;
      }
      if (keyRequired && !keyGroup) {
        window.alert("\u8bf7\u8f93\u5165\u5de5\u4f5c\u6d41 ID / \u4ee3\u53f7 / \u540d\u79f0\u3002");
        return;
      }
      if (keyRequired && !dialogState.user) {
        setAuthMessage("\u542f\u7528\u5bc6\u94a5\u524d\u8bf7\u5148\u767b\u5f55\u3002", true);
        syncDialogState();
        return;
      }

      if (!keyRequired) {
        cleanup({
          passphrase,
          keyRequired,
          keyGroup: "",
        });
        return;
      }

      setBusy(true);
      setAuthMessage("\u6b63\u5728\u540c\u6b65\u5de5\u4f5c\u6d41...");
      try {
        const group = await upsertPortalWorkflow(keyGroup);
        cleanup({
          passphrase,
          keyRequired,
          keyGroup: group?.code || keyGroup,
        });
      } catch (error) {
        setAuthMessage(error.message, true);
        setBusy(false);
        syncDialogState();
      }
    });

    overlay.appendChild(panel);
    document.body.appendChild(overlay);
    syncDialogState();
    void refreshPortalSession();
    passphraseInput.focus();
  });
};

applyCipherAppearance = function (node) {
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

  setWorkflowCipherWidgetLabel(getPasswordWidget(node), PASSWORD_DISPLAY_LABEL);
  setWorkflowCipherWidgetLabel(getAccessKeyWidget(node), ACCESS_KEY_DISPLAY_LABEL);

  for (const input of node.inputs || []) {
    input.label = " ";
  }
  for (const output of node.outputs || []) {
    output.label = " ";
  }

  node.color = "#1a1a2e";
  node.bgcolor = "#16213e";

  const nodeWidth = 320;
  const nodeHeight =
    160 + (getAccessKeyWidget(node) ? 38 : 0);

  node.serialize_widgets = true;
  node.computeSize = () => [nodeWidth, nodeHeight];

  node.getConnectionPos = function (is_input, _slot, out) {
    const res = out || new Float32Array(2);
    const cy = this.size[1] / 2;
    res[0] = is_input ? 0 : this.size[0];
    res[1] = cy;
    return res;
  };

  if (!node.__workflowCipherOriginalDrawForeground) {
    node.__workflowCipherOriginalDrawForeground = node.onDrawForeground;
  }
  const originalDrawForeground = node.__workflowCipherOriginalDrawForeground;
  node.onDrawForeground = function (ctx) {
    originalDrawForeground?.apply(this, arguments);

    const w = this.size[0];
    const h = this.size[1];
    const cy = h / 2;
    const DOT_R = 6;
    const DOT_COLOR = "#7ecfff";

    ctx.save();

    if ((this.inputs || []).length > 0) {
      ctx.beginPath();
      ctx.arc(0, cy, DOT_R, 0, Math.PI * 2);
      ctx.fillStyle = DOT_COLOR;
      ctx.fill();
      ctx.strokeStyle = "#ffffff44";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    if ((this.outputs || []).length > 0) {
      ctx.beginPath();
      ctx.arc(w, cy, DOT_R, 0, Math.PI * 2);
      ctx.fillStyle = DOT_COLOR;
      ctx.fill();
      ctx.strokeStyle = "#ffffff44";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

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

  if (typeof node.setSize === "function") {
    node.setSize([nodeWidth, nodeHeight]);
  } else {
    node.size = [nodeWidth, nodeHeight];
  }
  node.setDirtyCanvas?.(true, true);
};

installPasswordHandler = function (node) {
  if (!node) {
    return;
  }

  if (isLockedGroupNode(node) && !getPasswordWidget(node)) {
    const widget = node.addWidget("text", PASSWORD_WIDGET_NAME, "", async function () {
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
  setWorkflowCipherWidgetLabel(getPasswordWidget(node), PASSWORD_DISPLAY_LABEL);
  setWorkflowCipherWidgetLabel(getAccessKeyWidget(node), ACCESS_KEY_DISPLAY_LABEL);

  if (widget && !widget.__workflowCipherPasswordWrapped) {
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

  node.__workflowCipherAppearanceApplied = false;
  applyCipherAppearance(node);
};

addRestoreMenu = function (node, options) {
  if (!isLockedGroupNode(node) && !isVaultNode(node)) {
    return;
  }
  options.push(null);
  options.push({
    content: RESTORE_LABEL,
    callback: () => requestNodeRestore(node),
  });
};

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

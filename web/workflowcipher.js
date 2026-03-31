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
const PASSWORD_DISPLAY_LABEL = "\u5f00\u653e\u8282\u70b9\u5bc6\u7801";
const ACCESS_KEY_DISPLAY_LABEL = "\u6388\u6743\u5bc6\u94a5";
const PRODUCT_CODE_LABEL = "\u4ea7\u54c1\u7f16\u7801";
const RESTORE_BUTTON_LABEL = "\u5f00\u653e\u8282\u70b9";
const ENCRYPT_SINGLE_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6b64\u8282\u70b9`;
const ENCRYPT_MULTI_LABEL = `${BRAND_NAME} \u52a0\u5bc6\u6240\u9009\u8282\u70b9`;
const RESTORE_LABEL = `${BRAND_NAME} \u8f93\u5165\u5bc6\u7801\u5e76\u8fd8\u539f`;
const PORTAL_LABEL = `${BRAND_NAME} \u6388\u6743\u540e\u53f0`;
const FRONTEND_CONFIG_PATH = "/xljworkflowcipher/api/frontend-config";
const DEFAULT_PORTAL_PATH = "/xljworkflowcipher/portal";
const HARDCODED_API_BASE = "https://cf.xinlingjunai.net";
const HARDCODED_PORTAL_URL = `${HARDCODED_API_BASE}/xljworkflowcipher/portal`;

let frontendConfigCache = {
  api_base: "",
  portal_url: DEFAULT_PORTAL_PATH,
  remote_enabled: false,
};
let frontendConfigPromise = null;

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

function normalizedApiBase(config = frontendConfigCache) {
  return String(config?.api_base || "").trim().replace(/\/+$/, "");
}

function hasCrossOriginApiBase(config = frontendConfigCache) {
  const apiBase = normalizedApiBase(config);
  if (!apiBase) {
    return false;
  }
  try {
    return new URL(apiBase).origin !== window.location.origin;
  } catch (_error) {
    return false;
  }
}

async function requestRemoteJson(url, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };
  if (options.body !== undefined && !Object.keys(headers).some((name) => name.toLowerCase() === "content-type")) {
    headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(url, {
      credentials: "include",
      headers,
      ...options,
    });
  } catch (_error) {
    throw new Error("无法连接远程创作者后台，请检查域名、HTTPS 和 CORS 配置。");
  }

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("远程创作者后台返回了非 JSON 响应，请确认接口地址和登录状态。");
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.error) {
    throw new Error(data.error || `${BRAND_NAME} remote request failed: ${response.status}`);
  }
  return data;
}

async function requestBackendJson(path, options = {}, config = frontendConfigCache) {
  try {
    return await requestJson(path, options);
  } catch (localError) {
    const apiBase = normalizedApiBase(config) || HARDCODED_API_BASE;
    if (!apiBase) {
      throw localError;
    }

    try {
      return await requestRemoteJson(`${apiBase}${path}`, options);
    } catch (remoteError) {
      throw remoteError || localError;
    }
  }
}

async function getFrontendConfig(forceRefresh = false) {
  if (!frontendConfigPromise || forceRefresh) {
    frontendConfigPromise = requestJson(FRONTEND_CONFIG_PATH)
      .then((payload) => {
        frontendConfigCache = {
          ...frontendConfigCache,
          ...(payload || {}),
          api_base: payload?.api_base || frontendConfigCache.api_base || HARDCODED_API_BASE,
          portal_url: payload?.portal_url || frontendConfigCache.portal_url || HARDCODED_PORTAL_URL,
          remote_enabled: Boolean(payload?.remote_enabled ?? true),
        };
        return frontendConfigCache;
      })
      .catch((error) => {
        frontendConfigCache = {
          ...frontendConfigCache,
          api_base: normalizedApiBase(frontendConfigCache) || HARDCODED_API_BASE,
          portal_url:
            frontendConfigCache.portal_url && frontendConfigCache.portal_url !== DEFAULT_PORTAL_PATH
              ? frontendConfigCache.portal_url
              : HARDCODED_PORTAL_URL,
          remote_enabled: true,
        };
        if (forceRefresh) {
          return frontendConfigCache;
        }
        return frontendConfigCache;
      });
  }
  return frontendConfigPromise;
}

function openBrowserTab(url) {
  const popup = window.open(url, "_blank");
  if (popup) {
    popup.opener = null;
  }
  return popup;
}

async function openPortalPage() {
  const fallbackUrl =
    frontendConfigCache.portal_url && frontendConfigCache.portal_url !== DEFAULT_PORTAL_PATH
      ? frontendConfigCache.portal_url
      : HARDCODED_PORTAL_URL;
  try {
    const config = await getFrontendConfig();
    openBrowserTab(config?.portal_url || fallbackUrl);
  } catch (_error) {
    openBrowserTab(fallbackUrl);
  }
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

function extractSyncedWorkflowCode(payload, fallbackCode) {
  return (
    payload?.group?.code ||
    payload?.workflow?.code ||
    payload?.workflow?.workflow_code ||
    payload?.workflow?.group_code ||
    payload?.code ||
    payload?.workflow_code ||
    fallbackCode
  );
}

async function ensureRemoteWorkflowSynced(selectedNodes, options) {
  if (!options?.keyRequired || !options?.keyGroup) {
    return options?.keyGroup || "";
  }

  const config = await getFrontendConfig();
  try {
    await requestBackendJson("/xljworkflowcipher/api/me", {}, config);
  } catch (_error) {
    if (hasCrossOriginApiBase(config)) {
      throw new Error("\u8bf7\u5148登录创作者后台；如果已登录仍失败，请确认后端已允许跨域凭证（CORS + SameSite=None Cookie）。");
    }
    throw new Error("\u8bf7\u5148\u901a\u8fc7\u672c\u5730\u6388\u6743\u9875\u767b\u5f55\uff0c\u518d\u521b\u5efa\u5e26\u5bc6\u94a5\u6821\u9a8c\u7684\u52a0\u5bc6\u5de5\u4f5c\u6d41\u3002");
  }

  const workflowName = buildNodeTitle(selectedNodes) || options.keyGroup;
  const basePayload = {
    code: options.keyGroup,
    workflow_code: options.keyGroup,
    name: workflowName,
    workflow_name: workflowName,
    description: `Created from ${BRAND_NAME}`,
  };
  const attempts = [
    basePayload,
    {
      ...basePayload,
      key_count: 1,
      key_validity_days: 30,
    },
  ];

  let lastError = null;
  for (const payload of attempts) {
    try {
      const synced = await requestBackendJson("/xljworkflowcipher/api/workflows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }, config);
      return extractSyncedWorkflowCode(synced, options.keyGroup);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("\u540e\u53f0 workflow \u540c\u6b65\u5931\u8d25");
}

async function encryptSelectionToVault(selectedNodes, options) {
  const syncedKeyGroup = await ensureRemoteWorkflowSynced(selectedNodes, options);
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
      key_group: syncedKeyGroup,
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
  // Frontend should never auto-restore encrypted content based on license status.
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

getVisibleWidgetNames = function (_node) {
  return new Set([PASSWORD_WIDGET_NAME, ACCESS_KEY_WIDGET]);
};

promptEncryptionOptions = function () {
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
          \u8fd9\u91cc\u7ed1\u5b9a\u7684\u662f\u4ea7\u54c1\u7f16\u7801\uff0c\u4e0d\u662f\u6388\u6743\u65f6\u957f\u3002
          \u8bd5\u7528\u3001\u5929\u5361\u3001\u6b21\u6570\u5361\u3001\u9996\u6b21\u4f7f\u7528\u540e\u5f00\u59cb\u8ba1\u65f6\u3001\u8bbe\u5907\u7ed1\u5b9a\u7b49\u89c4\u5219\uff0c\u90fd\u5e94\u7531\u6388\u6743\u540e\u53f0\u5728\u53d1\u5361\u65f6\u51b3\u5b9a\u3002
        </p>
        <div data-backend-hint style="margin-top:10px;color:#71d9cb;font-size:12px;line-height:1.6;"></div>
      </div>
      <label style="display:grid;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">${PASSWORD_DISPLAY_LABEL}</span>
        <input name="passphrase" type="password" autocomplete="new-password" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
      </label>
      <label style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,0.04);">
        <input name="key_required" type="checkbox" style="inline-size:18px;block-size:18px;" />
        <span>\u542f\u7528\u5bc6\u94a5\u6821\u9a8c</span>
      </label>
      <label style="display:grid;gap:8px;">
        <span style="color:#9fb0d0;font-size:14px;">${PRODUCT_CODE_LABEL}</span>
        <input name="key_group" placeholder="\u4e0d\u542f\u7528\u65f6\u53ef\u7559\u7a7a" style="width:100%;padding:12px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#0d1320;color:#eef3ff;" />
        <span data-key-hint style="color:#7082a6;font-size:12px;line-height:1.5;"></span>
      </label>
      <div style="display:flex;gap:12px;justify-content:flex-end;">
        <button type="button" data-action="portal" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">\u6388\u6743\u540e\u53f0</button>
        <button type="button" data-action="cancel" style="padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:transparent;color:#eef3ff;">\u53d6\u6d88</button>
        <button type="submit" style="padding:11px 16px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);background:#4ec7b9;color:#082420;font-weight:700;">\u786e\u8ba4\u52a0\u5bc6</button>
      </div>
    `;

    const passphraseInput = panel.querySelector('input[name="passphrase"]');
    const keyRequiredInput = panel.querySelector('input[name="key_required"]');
    const keyGroupInput = panel.querySelector('input[name="key_group"]');
    const keyHint = panel.querySelector("[data-key-hint]");
    const backendHint = panel.querySelector("[data-backend-hint]");

    function cleanup(value) {
      overlay.remove();
      resolve(value);
    }

    function syncBackendHint(config = frontendConfigCache) {
      if (config?.remote_enabled) {
        backendHint.textContent = `\u5df2\u914d\u7f6e\u8fdc\u7a0b\u6388\u6743\u540e\u53f0: ${config.portal_url}`;
      } else {
        backendHint.textContent = "\u5f53\u524d\u672a\u914d\u7f6e\u8fdc\u7a0b\u6388\u6743\u540e\u53f0\uff0c\u6309\u94ae\u4f1a\u6253\u5f00\u63d2\u4ef6\u5185\u7f6e\u9875\u9762\u3002";
      }
    }

    function syncKeyHint() {
      if (keyRequiredInput.checked) {
        keyGroupInput.placeholder = "\u4f8b\u5982: grok_video_pro";
        keyHint.textContent = "\u542f\u7528\u540e\u5fc5\u987b\u586b\u5199\u4ea7\u54c1\u7f16\u7801\u3002\u7528\u6237\u5b9e\u9645\u62ff\u5230\u7684\u5bc6\u94a5\u65f6\u957f\u3001\u6b21\u6570\u3001\u8bd5\u7528\u89c4\u5219\u548c\u8bbe\u5907\u7b56\u7565\uff0c\u90fd\u7531\u6388\u6743\u540e\u53f0\u53d1\u5361\u65f6\u51b3\u5b9a\u3002";
      } else {
        keyGroupInput.placeholder = "\u4e0d\u542f\u7528\u65f6\u53ef\u7559\u7a7a";
        keyHint.textContent = "\u4e0d\u542f\u7528\u65f6\u53ef\u7559\u7a7a\u3002\u8fd9\u4e2a\u5b57\u6bb5\u53ea\u7528\u4e8e\u628a\u52a0\u5bc6\u5de5\u4f5c\u6d41\u7ed1\u5b9a\u5230\u540e\u53f0\u7684\u67d0\u4e2a\u4ea7\u54c1\u7f16\u7801\u3002";
      }
    }

    keyRequiredInput.addEventListener("change", syncKeyHint);
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
        window.alert("\u8bf7\u5148\u586b\u5199\u5f00\u653e\u8282\u70b9\uff08\u89e3\u5bc6\u8282\u70b9\uff09\u3002");
        return;
      }
      if (keyRequired && !keyGroup) {
        window.alert("\u542f\u7528\u5bc6\u94a5\u540e\uff0c\u5fc5\u987b\u586b\u5199\u5bc6\u94a5\u3002");
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
    syncBackendHint();
    syncKeyHint();
    void getFrontendConfig().then((config) => syncBackendHint(config));
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
    void getFrontendConfig();
    injectCanvasContextMenu();
  },
});

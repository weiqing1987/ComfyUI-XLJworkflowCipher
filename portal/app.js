const PAGE_SIZE = 10;
const PAGE_MODE = document.body.dataset.page || "main";

const state = {
  user: null,
  groups: [],
  activePage: 1,
  expandedGroups: new Set(),
};

const statusEl = document.getElementById("status");
const authPanel = document.getElementById("authPanel");
const dashboard = document.getElementById("dashboard");
const welcomeText = document.getElementById("welcomeText");
const groupsList = document.getElementById("groupsList");
const recycleList = document.getElementById("recycleList");
const expiringList = document.getElementById("expiringList");
const groupsPagination = document.getElementById("groupsPagination");
const groupTemplate = document.getElementById("groupTemplate");
const refreshButton = document.getElementById("refreshButton");
const passwordForm = document.getElementById("passwordForm");
const passwordPanel = document.getElementById("passwordPanel");
const passwordToggleButton = document.getElementById("passwordToggleButton");
const passwordCloseButton = document.getElementById("passwordCloseButton");

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ffd0d5" : "";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.error) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

function statusClass(status) {
  if (status === "disabled") {
    return "disabled";
  }
  if (status === "destroyed" || status === "expired") {
    return "destroyed";
  }
  return "";
}

function userDisplayId(user) {
  return String(user?.id || 0).padStart(6, "0");
}

function activeGroups() {
  return state.groups.filter((group) => group.status !== "destroyed");
}

function recycledGroups() {
  return state.groups.filter((group) => group.status === "destroyed");
}

function expiringWithinOneDay(key) {
  if (!key.expires_at) {
    return false;
  }
  const remainingMs = new Date(key.expires_at).getTime() - Date.now();
  return remainingMs > 0 && remainingMs <= 24 * 60 * 60 * 1000;
}

function expiringKeys() {
  const rows = [];
  for (const group of activeGroups()) {
    for (const key of group.keys || []) {
      if (expiringWithinOneDay(key)) {
        rows.push({ group, key });
      }
    }
  }
  return rows.sort((a, b) => new Date(a.key.expires_at) - new Date(b.key.expires_at));
}

function formatRemaining(expiresAt) {
  if (!expiresAt) {
    return "剩余：不限时";
  }
  const remainingMs = new Date(expiresAt).getTime() - Date.now();
  if (remainingMs <= 0) {
    return "剩余：已过期";
  }
  const totalHours = Math.floor(remainingMs / (60 * 60 * 1000));
  const days = Math.floor(totalHours / 24);
  const hours = totalHours % 24;
  if (days > 0) {
    return `剩余：${days}天${hours}小时`;
  }
  const minutes = Math.max(1, Math.floor((remainingMs % (60 * 60 * 1000)) / (60 * 1000)));
  return `剩余：${hours}小时${minutes}分钟`;
}

function recycleDeadlineText(group) {
  if (!group.recoverable_until) {
    return "已移入回收站";
  }
  return `可恢复至 ${new Date(group.recoverable_until).toLocaleString("zh-CN")}`;
}

function pageCount(total) {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

function currentPageGroups() {
  const groups = activeGroups();
  const totalPages = pageCount(groups.length);
  state.activePage = Math.min(state.activePage, totalPages);
  const start = (state.activePage - 1) * PAGE_SIZE;
  return groups.slice(start, start + PAGE_SIZE);
}

function renderStats() {
  const workflowCount = document.getElementById("workflowCount");
  const expiringCount = document.getElementById("expiringCount");
  if (workflowCount) {
    workflowCount.textContent = String(activeGroups().length);
  }
  if (expiringCount) {
    expiringCount.textContent = String(expiringKeys().length);
  }
}

function renderPagination() {
  if (!groupsPagination) {
    return;
  }
  const totalGroups = activeGroups().length;
  const totalPages = pageCount(totalGroups);
  groupsPagination.innerHTML = "";
  if (totalGroups <= PAGE_SIZE) {
    return;
  }

  const prevButton = document.createElement("button");
  prevButton.type = "button";
  prevButton.className = "ghost";
  prevButton.textContent = "上一页";
  prevButton.disabled = state.activePage <= 1;
  prevButton.addEventListener("click", () => {
    state.activePage = Math.max(1, state.activePage - 1);
    renderGroups();
  });

  const info = document.createElement("span");
  info.className = "hint";
  info.textContent = `第 ${state.activePage} / ${totalPages} 页，共 ${totalGroups} 个工作流`;

  const nextButton = document.createElement("button");
  nextButton.type = "button";
  nextButton.className = "ghost";
  nextButton.textContent = "下一页";
  nextButton.disabled = state.activePage >= totalPages;
  nextButton.addEventListener("click", () => {
    state.activePage = Math.min(totalPages, state.activePage + 1);
    renderGroups();
  });

  groupsPagination.append(prevButton, info, nextButton);
}

async function refreshGroups() {
  if (!state.user) {
    return;
  }
  const payload = await requestJson("/xljworkflowcipher/api/workflows");
  state.groups = payload.groups || [];
  renderGroups();
}

function createKeyRow(group, key) {
  const row = document.createElement("div");
  row.className = "key-row";
  row.innerHTML = `
    <div class="key-value">${key.access_key}</div>
    <div class="key-note-editor">
      <input class="key-note-input" value="${String(key.note || "").replace(/"/g, "&quot;")}" placeholder="客户名称 / 公司名称" />
      <button type="button" class="ghost save-note">保存备注</button>
    </div>
    <span class="pill ${statusClass(key.status)}">${key.status}</span>
    <div class="hint">${formatRemaining(key.expires_at)}</div>
    <div class="key-actions">
      <button type="button" class="ghost copy-key">复制</button>
      <button type="button" class="danger disable-key">停用</button>
    </div>
  `;

  const noteInput = row.querySelector(".key-note-input");

  row.querySelector(".save-note").addEventListener("click", async () => {
    try {
      const payload = await requestJson(
        `/xljworkflowcipher/api/workflows/${group.id}/keys/${key.id}/note`,
        {
          method: "POST",
          body: JSON.stringify({ note: noteInput.value || "" }),
        }
      );
      setStatus(`已保存备注：${payload.key.note || "空备注"}`);
      await refreshGroups();
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  row.querySelector(".copy-key").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(key.access_key);
      setStatus(`已复制密钥 ${key.access_key}`);
    } catch (error) {
      setStatus(`复制失败: ${error.message}`, true);
    }
  });

  row.querySelector(".disable-key").addEventListener("click", async () => {
    const confirmed = window.confirm(`确认停用密钥 ${key.access_key} 吗？停用后会从列表移除。`);
    if (!confirmed) {
      return;
    }
    try {
      await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/keys/${key.id}/delete`, {
        method: "POST",
      });
      setStatus(`已停用密钥 ${key.access_key}`);
      await refreshGroups();
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  return row;
}

function renderGroupCard(group, container, recycled = false) {
  const fragment = groupTemplate.content.cloneNode(true);
  const name = fragment.querySelector(".group-name");
  const code = fragment.querySelector(".group-code");
  const status = fragment.querySelector(".group-status");
  const activeActions = fragment.querySelector(".active-actions");
  const recycleActions = fragment.querySelector(".recycle-actions");
  const recycleDeadline = fragment.querySelector(".recycle-deadline");
  const expirySelect = fragment.querySelector(".expiry-select");
  const generateKeyButton = fragment.querySelector(".generate-key");
  const disableGroupButton = fragment.querySelector(".disable-group");
  const destroyGroupButton = fragment.querySelector(".destroy-group");
  const restoreGroupButton = fragment.querySelector(".restore-group");
  const deleteGroupButton = fragment.querySelector(".delete-group");
  const keySummary = fragment.querySelector(".key-summary");
  const toggleKeysButton = fragment.querySelector(".toggle-keys");
  const keysTable = fragment.querySelector(".keys-table");

  name.textContent = group.name;
  code.textContent = `工作流编号: ${group.code}`;
  status.textContent = recycled ? "回收站" : group.status;
  const cls = statusClass(group.status);
  if (cls) {
    status.classList.add(cls);
  }

  const keyCount = Array.isArray(group.keys) ? group.keys.length : 0;
  keySummary.textContent = keyCount ? `当前有效密钥 ${keyCount} 个` : "当前没有有效密钥";
  const expanded = state.expandedGroups.has(group.id);
  keysTable.classList.toggle("hidden", !expanded);
  toggleKeysButton.textContent = expanded ? "收起" : "展开";
  toggleKeysButton.addEventListener("click", () => {
    if (state.expandedGroups.has(group.id)) {
      state.expandedGroups.delete(group.id);
    } else {
      state.expandedGroups.add(group.id);
    }
    renderGroups();
  });

  if (!keyCount) {
    keysTable.innerHTML = '<p class="hint">当前没有有效密钥</p>';
  } else {
    keysTable.innerHTML = "";
    for (const key of group.keys) {
      keysTable.appendChild(createKeyRow(group, key));
    }
  }

  if (recycled) {
    activeActions?.classList.add("hidden");
    recycleActions?.classList.remove("hidden");
    if (recycleDeadline) {
      recycleDeadline.textContent = recycleDeadlineText(group);
    }
    restoreGroupButton?.addEventListener("click", async () => {
      try {
        await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/restore`, {
          method: "POST",
        });
        setStatus(`已恢复工作流 ${group.code}`);
        await refreshGroups();
      } catch (error) {
        setStatus(error.message, true);
      }
    });
    deleteGroupButton?.addEventListener("click", async () => {
      const confirmed = window.confirm(`确认彻底删除 ${group.name} 吗？删除后无法恢复。`);
      if (!confirmed) {
        return;
      }
      try {
        await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/delete`, {
          method: "POST",
        });
        setStatus(`已彻底删除工作流 ${group.code}`);
        await refreshGroups();
      } catch (error) {
        setStatus(error.message, true);
      }
    });
    container.appendChild(fragment);
    return;
  }

  recycleActions?.classList.add("hidden");
  generateKeyButton?.addEventListener("click", async () => {
    try {
      const payload = await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/keys`, {
        method: "POST",
        body: JSON.stringify({ expiry_mode: expirySelect.value }),
      });
      setStatus(`已生成密钥 ${payload.key.access_key}`);
      state.expandedGroups.add(group.id);
      await refreshGroups();
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  disableGroupButton?.addEventListener("click", async () => {
    try {
      await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/disable`, {
        method: "POST",
      });
      setStatus(`已停用工作流 ${group.code}`);
      await refreshGroups();
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  destroyGroupButton?.addEventListener("click", async () => {
    const confirmed = window.confirm(`确认将 ${group.name} 移入回收站吗？`);
    if (!confirmed) {
      return;
    }
    try {
      await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/destroy`, {
        method: "POST",
      });
      setStatus(`已将工作流 ${group.code} 移入回收站`);
      await refreshGroups();
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  container.appendChild(fragment);
}

function renderMainPage() {
  renderStats();
  if (!groupsList) {
    return;
  }
  groupsList.innerHTML = "";
  const groups = currentPageGroups();
  if (!groups.length) {
    groupsList.innerHTML = '<p class="hint">还没有可管理的工作流</p>';
  } else {
    for (const group of groups) {
      renderGroupCard(group, groupsList, false);
    }
  }
  renderPagination();
}

function renderRecyclePage() {
  if (!recycleList) {
    return;
  }
  recycleList.innerHTML = "";
  const groups = recycledGroups();
  if (!groups.length) {
    recycleList.innerHTML = '<p class="hint">回收站目前为空</p>';
    return;
  }
  for (const group of groups) {
    renderGroupCard(group, recycleList, true);
  }
}

function renderExpiringPage() {
  if (!expiringList) {
    return;
  }
  expiringList.innerHTML = "";
  const rows = expiringKeys();
  if (!rows.length) {
    expiringList.innerHTML = '<p class="hint">未来 24 小时内没有即将到期的密钥</p>';
    return;
  }
  for (const { group, key } of rows) {
    const row = document.createElement("div");
    row.className = "key-row";
    row.innerHTML = `
      <div class="key-value">${key.access_key}</div>
      <div class="hint">${group.name} / 编号 ${group.code}</div>
      <span class="pill ${statusClass(key.status)}">${key.status}</span>
      <div class="hint">${formatRemaining(key.expires_at)}</div>
      <div class="key-actions">
        <button type="button" class="ghost copy-key">复制</button>
      </div>
    `;
    row.querySelector(".copy-key").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(key.access_key);
        setStatus(`已复制密钥 ${key.access_key}`);
      } catch (error) {
        setStatus(`复制失败: ${error.message}`, true);
      }
    });
    expiringList.appendChild(row);
  }
}

function renderGroups() {
  if (PAGE_MODE === "recycle") {
    renderRecyclePage();
    return;
  }
  if (PAGE_MODE === "expiring") {
    renderExpiringPage();
    return;
  }
  renderMainPage();
}

function renderAuthState() {
  const loggedIn = Boolean(state.user);
  authPanel.classList.toggle("hidden", loggedIn);
  dashboard.classList.toggle("hidden", !loggedIn);
  if (loggedIn) {
    welcomeText.textContent = `当前用户：${state.user.username}  ID:${userDisplayId(state.user)}`;
    renderGroups();
  }
}

function installVisibilityToggles() {
  for (const button of document.querySelectorAll(".toggle-visibility")) {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.target);
      if (!target) {
        return;
      }
      target.type = target.type === "password" ? "text" : "password";
      button.textContent = target.type === "password" ? "显示" : "隐藏";
    });
  }
}

function installPasswordPanel() {
  passwordToggleButton?.addEventListener("click", () => {
    passwordPanel?.classList.toggle("hidden");
  });
  passwordCloseButton?.addEventListener("click", () => {
    passwordPanel?.classList.add("hidden");
  });
}

async function bootstrap() {
  try {
    const payload = await requestJson("/xljworkflowcipher/api/me");
    state.user = payload.user;
    state.groups = payload.groups || [];
    setStatus("已连接密钥服务。");
  } catch (_error) {
    state.user = null;
    state.groups = [];
    setStatus("请先注册或登录。");
  }
  renderAuthState();
}

document.getElementById("authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const payload = await requestJson("/xljworkflowcipher/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        password: form.get("password"),
      }),
    });
    state.user = payload.user;
    state.activePage = 1;
    setStatus(`欢迎回来，${payload.user.username}`);
    await refreshGroups();
    renderAuthState();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("registerButton").addEventListener("click", async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  try {
    const payload = await requestJson("/xljworkflowcipher/api/register", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    state.user = payload.user;
    state.activePage = 1;
    setStatus(`注册成功，已登录 ${payload.user.username}`);
    await refreshGroups();
    renderAuthState();
  } catch (error) {
    setStatus(error.message, true);
  }
});

refreshButton?.addEventListener("click", async () => {
  try {
    await refreshGroups();
    setStatus("已刷新。");
  } catch (error) {
    setStatus(error.message, true);
  }
});

passwordForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const newPassword = String(form.get("new_password") || "");
  const confirmPassword = String(form.get("confirm_password") || "");
  if (newPassword !== confirmPassword) {
    setStatus("两次输入的新密码不一致。", true);
    return;
  }
  try {
    await requestJson("/xljworkflowcipher/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: form.get("current_password"),
        new_password: newPassword,
      }),
    });
    event.currentTarget.reset();
    passwordPanel?.classList.add("hidden");
    setStatus("密码修改成功。");
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  try {
    await requestJson("/xljworkflowcipher/api/logout", { method: "POST" });
  } catch (_error) {
  } finally {
    state.user = null;
    state.groups = [];
    state.activePage = 1;
    state.expandedGroups.clear();
    passwordPanel?.classList.add("hidden");
    setStatus("已退出登录。");
    renderAuthState();
  }
});

installVisibilityToggles();
installPasswordPanel();
void bootstrap();

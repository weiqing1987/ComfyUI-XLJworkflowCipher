const state = {
  user: null,
  groups: [],
};

const statusEl = document.getElementById("status");
const authPanel = document.getElementById("authPanel");
const dashboard = document.getElementById("dashboard");
const welcomeText = document.getElementById("welcomeText");
const groupsList = document.getElementById("groupsList");
const groupTemplate = document.getElementById("groupTemplate");

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

function expiryLabel(mode, expiresAt) {
  if (mode === "unlimited" || !expiresAt) {
    return "不限时";
  }
  return new Date(expiresAt).toLocaleString();
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

function applyStatusClass(element, status) {
  const cls = statusClass(status);
  if (cls) {
    element.classList.add(cls);
  }
}

async function refreshGroups() {
  if (!state.user) {
    return;
  }
  const payload = await requestJson("/xljworkflowcipher/api/workflows");
  state.groups = payload.groups || [];
  renderGroups();
}

function renderGroups() {
  groupsList.innerHTML = "";

  if (!state.groups.length) {
    groupsList.innerHTML = "<p class=\"hint\">还没有创建任何工作流密钥组。</p>";
    return;
  }

  for (const group of state.groups) {
    const fragment = groupTemplate.content.cloneNode(true);
    const card = fragment.querySelector(".group-card");
    const name = fragment.querySelector(".group-name");
    const code = fragment.querySelector(".group-code");
    const status = fragment.querySelector(".group-status");
    const expirySelect = fragment.querySelector(".expiry-select");
    const keysTable = fragment.querySelector(".keys-table");

    name.textContent = group.name;
    code.textContent = `编号: ${group.code}`;
    status.textContent = group.status;
    applyStatusClass(status, group.status);

    fragment.querySelector(".generate-key").addEventListener("click", async () => {
      try {
        const payload = await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/keys`, {
          method: "POST",
          body: JSON.stringify({ expiry_mode: expirySelect.value }),
        });
        setStatus(`已生成密钥: ${payload.key.access_key}`);
        await refreshGroups();
      } catch (error) {
        setStatus(error.message, true);
      }
    });

    fragment.querySelector(".disable-group").addEventListener("click", async () => {
      try {
        await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/disable`, {
          method: "POST",
        });
        setStatus(`已停用 ${group.code}`);
        await refreshGroups();
      } catch (error) {
        setStatus(error.message, true);
      }
    });

    fragment.querySelector(".destroy-group").addEventListener("click", async () => {
      const confirmed = window.confirm(`确认销毁 ${group.code} 吗？销毁后会解除密钥校验。`);
      if (!confirmed) {
        return;
      }
      try {
        await requestJson(`/xljworkflowcipher/api/workflows/${group.id}/destroy`, {
          method: "POST",
        });
        setStatus(`已销毁 ${group.code}`);
        await refreshGroups();
      } catch (error) {
        setStatus(error.message, true);
      }
    });

    if (!group.keys.length) {
      keysTable.innerHTML = "<p class=\"hint\">还没有生成密钥。</p>";
    } else {
      for (const key of group.keys) {
        const row = document.createElement("div");
        row.className = "key-row";
        row.innerHTML = `
          <div class="key-value">${key.access_key}</div>
          <span class="pill ${statusClass(key.status)}">${key.status}</span>
          <div class="hint">${expiryLabel(key.expiry_mode, key.expires_at)}</div>
          <button type="button" class="ghost">复制</button>
        `;
        row.querySelector("button").addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(key.access_key);
            setStatus(`已复制密钥 ${key.access_key}`);
          } catch (error) {
            setStatus(`复制失败: ${error.message}`, true);
          }
        });
        keysTable.appendChild(row);
      }
    }

    groupsList.appendChild(card);
  }
}

function renderAuthState() {
  const loggedIn = Boolean(state.user);
  authPanel.classList.toggle("hidden", loggedIn);
  dashboard.classList.toggle("hidden", !loggedIn);

  if (loggedIn) {
    welcomeText.textContent = `当前账号: ${state.user.username}`;
    renderGroups();
  }
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
    setStatus(`注册成功，已登录 ${payload.user.username}`);
    await refreshGroups();
    renderAuthState();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("workflowForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await requestJson("/xljworkflowcipher/api/workflows", {
      method: "POST",
      body: JSON.stringify({
        code: form.get("code"),
        name: form.get("name"),
      }),
    });
    event.currentTarget.reset();
    setStatus("工作流密钥组已保存。");
    await refreshGroups();
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("refreshButton").addEventListener("click", async () => {
  try {
    await refreshGroups();
    setStatus("已刷新。");
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  try {
    await requestJson("/xljworkflowcipher/api/logout", {
      method: "POST",
    });
    state.user = null;
    state.groups = [];
    renderAuthState();
    setStatus("已退出登录。");
  } catch (error) {
    setStatus(error.message, true);
  }
});

bootstrap();

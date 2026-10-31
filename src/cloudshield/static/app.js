"use strict";

const welcomeView = document.querySelector("#welcome-view");
const authView = document.querySelector("#auth-view");
const dashboardView = document.querySelector("#dashboard-view");
const signinForm = document.querySelector("#signin-form");
const signupForm = document.querySelector("#signup-form");
const signinStatus = document.querySelector("#signin-status");
const signupStatus = document.querySelector("#signup-status");
const signinIdentifier = document.querySelector("#signin-identifier");
const configSelect = document.querySelector("#config-select");
const scanButton = document.querySelector("#scan-button");
const scanForm = document.querySelector("#scan-form");
const scanStatus = document.querySelector("#scan-status");
const uploadForm = document.querySelector("#upload-form");
const configurationFileInput = document.querySelector("#configuration-file");
const uploadButton = document.querySelector("#upload-button");
const uploadStatus = document.querySelector("#upload-status");
const resultsSection = document.querySelector("#results");
const findingList = document.querySelector("#finding-list");
const findingCount = document.querySelector("#finding-count");
const customForm = document.querySelector("#custom-form");
const customNameInput = document.querySelector("#custom-name");
const customJsonInput = document.querySelector("#custom-json");
const customStatus = document.querySelector("#custom-status");
const customList = document.querySelector("#custom-list");
const saveCustomButton = document.querySelector("#save-custom-button");
const cancelEditButton = document.querySelector("#cancel-edit-button");
const signinTab = document.querySelector("#show-signin");
const signupTab = document.querySelector("#show-signup");
const signinNav = document.querySelector("#nav-signin");
const signupNav = document.querySelector("#nav-signup");
const homeNav = document.querySelector("#nav-home");
const dashboardNav = document.querySelector("#nav-dashboard");
const accountLabel = document.querySelector("#account-label");
const signoutButton = document.querySelector("#signout-button");
const ollamaModelHint = document.querySelector("#ollama-model-hint");
const aiSettingsStatus = document.querySelector("#ai-settings-status");

const defaultConfiguration = {
  schema_version: "1.0",
  scenario_id: "my-example",
  label: "secure",
  resources: [
    {
      resource_id: "my-bucket",
      resource_type: "s3_bucket",
      config: { default_encryption: { SSEAlgorithm: "AES256" } },
    },
  ],
};

let csrfToken = "";
let editingConfigurationId = null;
let workspaceVersion = 0;
let explanationRequestInFlight = false;

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle("error", isError);
}

function setAuthStatus(form, message, isError = false) {
  setStatus(form === "signin" ? signinStatus : signupStatus, message, isError);
}

function clearWorkspace() {
  workspaceVersion += 1;
  resultsSection.hidden = true;
  findingList.replaceChildren();
  findingCount.textContent = "";
  customList.replaceChildren();
  customForm.reset();
  uploadForm.reset();
  setStatus(uploadStatus, "");
  customJsonInput.value = JSON.stringify(defaultConfiguration, null, 2);
  editingConfigurationId = null;
  saveCustomButton.textContent = "Save private example";
  cancelEditButton.hidden = true;
  configSelect.replaceChildren(new Option("Sign in to load examples", ""));
  configSelect.disabled = true;
  scanButton.disabled = true;
}

async function refreshCsrfToken() {
  const response = await fetch("/api/csrf-token");
  if (!response.ok) throw new Error("Could not start a secure session. Reload the page and try again.");
  const payload = await response.json();
  csrfToken = payload.csrf_token;
}

async function apiRequest(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    if (!csrfToken) await refreshCsrfToken();
    headers.set("X-CSRFToken", csrfToken);
  }
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response;
  try {
    response = await fetch(path, { ...options, method, headers });
  } catch {
    throw new Error("Could not connect to CloudShield. Check your connection and try again.");
  }
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    if (response.ok) return payload;
  }
  if (response.status === 503 && payload.available === false) return payload;
  if (response.status === 401) {
    showAuth("signin");
    setAuthStatus("signin", "Your session has ended. Sign in again to continue.", true);
    throw new Error("Your session has ended. Sign in again to continue.");
  }
  if (!response.ok) {
    const error = new Error(payload.error || "Something went wrong. Please try again.");
    error.status = response.status;
    error.retryAfter = response.headers.get("Retry-After");
    throw error;
  }
  return payload;
}

function showAuth(mode = "signin") {
  clearWorkspace();
  welcomeView.hidden = true;
  dashboardView.hidden = true;
  authView.hidden = false;
  signinForm.hidden = mode !== "signin";
  signupForm.hidden = mode !== "signup";
  signinTab.classList.toggle("active", mode === "signin");
  signupTab.classList.toggle("active", mode === "signup");
  signinTab.setAttribute("aria-selected", String(mode === "signin"));
  signupTab.setAttribute("aria-selected", String(mode === "signup"));
  signinNav.hidden = true;
  signupNav.hidden = true;
  homeNav.hidden = false;
  dashboardNav.hidden = true;
  accountLabel.hidden = true;
  signoutButton.hidden = true;
  history.replaceState(null, "", `/?view=${mode}`);
  (mode === "signin" ? signinIdentifier : document.querySelector("#signup-email")).focus();
}

function showWelcome() {
  clearWorkspace();
  welcomeView.hidden = false;
  authView.hidden = true;
  dashboardView.hidden = true;
  signinNav.hidden = false;
  signupNav.hidden = false;
  homeNav.hidden = true;
  dashboardNav.hidden = true;
  accountLabel.hidden = true;
  signoutButton.hidden = true;
  history.replaceState(null, "", "/");
}

function showDashboard(user) {
  workspaceVersion += 1;
  welcomeView.hidden = true;
  authView.hidden = true;
  dashboardView.hidden = false;
  signinNav.hidden = true;
  signupNav.hidden = true;
  homeNav.hidden = true;
  dashboardNav.hidden = false;
  accountLabel.hidden = false;
  accountLabel.textContent = user.username;
  signoutButton.hidden = false;
  history.replaceState(null, "", "/dashboard");
  void loadWorkspace();
}

function makeFindingCard(finding, configId, uploadedFile = null) {
  const card = makeElement("article", "finding-card");
  const title = makeElement("div", "finding-title");
  title.append(
    makeElement("span", "rule-id", finding.rule_id),
    makeElement("h3", "", finding.rule_name),
    makeElement("span", `severity ${finding.severity.toLowerCase()}`, finding.severity),
  );
  card.append(
    title,
    makeElement("p", "resource", `Resource: ${finding.resource_id}`),
    makeElement("p", "explanation", finding.explanation),
    makeElement("h4", "evidence-heading", "Evidence found"),
  );

  const evidence = makeElement("ul", "evidence");
  for (const item of finding.evidence) evidence.append(makeElement("li", "", item));
  card.append(evidence);

  const explainButton = makeElement("button", "button explain-button", "Explain with sources");
  explainButton.type = "button";
  explainButton.disabled = explanationRequestInFlight;
  const explanationPanel = makeElement("div", "ai-explanation");
  explanationPanel.hidden = true;
  explainButton.addEventListener("click", () => {
    void requestExplanation(explainButton, explanationPanel, configId, finding, uploadedFile);
  });
  card.append(explainButton, explanationPanel);
  return card;
}

function displayFindings(findings, configId, uploadedFile = null) {
  findingList.replaceChildren();
  resultsSection.hidden = false;
  findingCount.textContent = `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`;
  if (!findings.length) {
    findingList.append(makeElement("p", "empty-state", "This valid configuration produced no findings in the applicable checks."));
    return;
  }
  for (const finding of findings) findingList.append(makeFindingCard(finding, configId, uploadedFile));
}

async function requestExplanation(button, panel, configId, finding, uploadedFile = null) {
  const version = workspaceVersion;
  if (explanationRequestInFlight) return;
  explanationRequestInFlight = true;
  button.disabled = true;
  for (const explainButton of document.querySelectorAll(".explain-button")) {
    explainButton.disabled = true;
  }
  button.textContent = "Preparing explanation…";
  panel.hidden = false;
  panel.replaceChildren(makeElement("p", "", "Checking the finding, retrieving trusted documentation, and asking local Ollama…"));
  try {
    let endpoint = "/api/explain";
    let body;
    if (uploadedFile) {
      endpoint = "/api/explain-upload";
      body = new FormData();
      body.append("configuration_file", uploadedFile);
      body.append("rule_id", finding.rule_id);
      body.append("resource_id", finding.resource_id);
    } else {
      body = JSON.stringify({
        config_id: configId,
        rule_id: finding.rule_id,
        resource_id: finding.resource_id,
      });
    }
    const payload = await apiRequest(endpoint, {
      method: "POST",
      body,
    });
    if (version !== workspaceVersion) return;
    panel.replaceChildren(makeElement("p", "", payload.explanation));
    if (payload.sources && payload.sources.length) {
      panel.append(makeElement("h4", "", "Retrieved sources"));
      const sourceList = makeElement("ul", "source-list");
      for (const source of payload.sources) {
        const item = makeElement("li", "");
        if (typeof source.url === "string" && source.url.startsWith("https://docs.aws.amazon.com/")) {
          const link = makeElement("a", "", `${source.title} (${source.source_id})`);
          link.href = source.url;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          item.append(link);
        } else {
          item.textContent = `${source.title} (${source.source_id})`;
        }
        sourceList.append(item);
      }
      panel.append(sourceList);
    }
  } catch (error) {
    if (version !== workspaceVersion) return;
    panel.replaceChildren(makeElement("p", "error-text", error.message));
  } finally {
    explanationRequestInFlight = false;
    for (const explainButton of document.querySelectorAll(".explain-button")) {
      explainButton.disabled = false;
    }
    if (version === workspaceVersion) {
      button.disabled = false;
      button.textContent = "Explain with sources";
    }
  }
}

async function loadConfigurations() {
  const version = workspaceVersion;
  configSelect.disabled = true;
  scanButton.disabled = true;
  try {
    const configurations = await apiRequest("/api/configs");
    if (version !== workspaceVersion) return;
    configSelect.replaceChildren(new Option("Select an example to scan", ""));
    for (const config of configurations) {
      const label = config.kind === "custom" ? `My example · ${config.name}` : `Built-in · ${config.name}`;
      configSelect.add(new Option(label, config.id));
    }
    configSelect.disabled = configurations.length === 0;
    scanButton.disabled = configurations.length === 0;
    setStatus(
      scanStatus,
      configurations.length
        ? `${configurations.length} examples ready.`
        : "No examples are available right now.",
      configurations.length === 0,
    );
  } catch (error) {
    if (version !== workspaceVersion) return;
    setStatus(scanStatus, error.message, true);
  }
}

function resetCustomForm() {
  editingConfigurationId = null;
  customForm.reset();
  customJsonInput.value = JSON.stringify(defaultConfiguration, null, 2);
  saveCustomButton.textContent = "Save private example";
  cancelEditButton.hidden = true;
}

function fillCustomForm(configuration) {
  editingConfigurationId = configuration.id;
  customNameInput.value = configuration.name;
  customJsonInput.value = JSON.stringify(configuration.configuration, null, 2);
  saveCustomButton.textContent = "Save changes";
  cancelEditButton.hidden = false;
  customNameInput.focus();
  setStatus(customStatus, `Editing ${configuration.name}.`);
}

function renderCustomConfigurations(configurations) {
  customList.replaceChildren();
  if (!configurations.length) {
    customList.append(makeElement("p", "custom-empty", "Your saved examples will appear here. Only you can view and change them."));
    return;
  }
  for (const configuration of configurations) {
    const item = makeElement("div", "custom-item");
    item.append(makeElement("span", "custom-item-name", configuration.name));
    const actions = makeElement("div", "custom-item-actions");
    const edit = makeElement("button", "", "Edit");
    edit.type = "button";
    edit.addEventListener("click", () => fillCustomForm(configuration));
    const remove = makeElement("button", "delete-action", "Delete");
    remove.type = "button";
    remove.addEventListener("click", () => {
      void deleteCustomConfiguration(configuration.id, configuration.name);
    });
    actions.append(edit, remove);
    item.append(actions);
    customList.append(item);
  }
}

async function loadCustomConfigurations() {
  const version = workspaceVersion;
  try {
    const configurations = await apiRequest("/api/custom-configs");
    if (version !== workspaceVersion) return;
    renderCustomConfigurations(configurations);
  } catch (error) {
    if (version !== workspaceVersion) return;
    setStatus(customStatus, error.message, true);
  }
}

async function loadAISettings() {
  try {
    const settings = await apiRequest("/api/settings/ai");
    if (typeof settings.model === "string" && settings.model) {
      const model = makeElement("code", "", settings.model);
      ollamaModelHint.replaceChildren(
        "Configured model: ",
        model,
        ". Change it with CLOUDSHIELD_OLLAMA_MODEL.",
      );
    } else {
      ollamaModelHint.textContent = "The local Ollama model is not configured.";
    }
    setStatus(aiSettingsStatus, settings.message, !settings.available);
  } catch (error) {
    setStatus(aiSettingsStatus, error.message, true);
  }
}

async function loadWorkspace() {
  await Promise.all([loadConfigurations(), loadCustomConfigurations(), loadAISettings()]);
}

async function deleteCustomConfiguration(configId, name) {
  if (!window.confirm(`Delete your private example “${name}”? This cannot be undone.`)) return;
  const version = workspaceVersion;
  try {
    await apiRequest(`/api/custom-configs/${encodeURIComponent(configId)}`, { method: "DELETE" });
    if (version !== workspaceVersion) return;
    setStatus(customStatus, "Your private example was deleted.");
    if (editingConfigurationId === configId) resetCustomForm();
    await loadWorkspace();
  } catch (error) {
    if (version !== workspaceVersion) return;
    setStatus(customStatus, error.message, true);
  }
}

document.querySelectorAll("[data-auth-view]").forEach((control) => {
  control.addEventListener("click", (event) => {
    event.preventDefault();
    showAuth(control.dataset.authView);
  });
});

signinTab.addEventListener("click", () => showAuth("signin"));
signupTab.addEventListener("click", () => showAuth("signup"));

signinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAuthStatus("signin", "Signing in…");
  const submitButton = signinForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    const payload = await apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        identifier: signinIdentifier.value,
        password: document.querySelector("#signin-password").value,
        remember_me: document.querySelector("#remember-me").checked,
      }),
    });
    signinForm.reset();
    await refreshCsrfToken();
    showDashboard(payload.user);
  } catch (error) {
    setAuthStatus("signin", error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAuthStatus("signup", "Creating your account…");
  const submitButton = signupForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    const email = document.querySelector("#signup-email").value;
    await apiRequest("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        email,
        username: document.querySelector("#signup-username").value,
        password: document.querySelector("#signup-password").value,
        confirm_password: document.querySelector("#signup-confirm").value,
      }),
    });
    signupForm.reset();
    showAuth("signin");
    signinIdentifier.value = email;
    setAuthStatus("signin", "Account created. Sign in with your new account.");
  } catch (error) {
    setAuthStatus("signup", error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});

signoutButton.addEventListener("click", async () => {
  signoutButton.disabled = true;
  try {
    await apiRequest("/api/auth/logout", { method: "POST", body: "{}" });
    await refreshCsrfToken();
    showWelcome();
  } catch (error) {
    setStatus(scanStatus, error.message, true);
  } finally {
    signoutButton.disabled = false;
  }
});

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!configSelect.value) {
    setStatus(scanStatus, "Choose an example before scanning.", true);
    return;
  }
  scanButton.disabled = true;
  const version = workspaceVersion;
  resultsSection.hidden = true;
  setStatus(scanStatus, "Running the deterministic security checks…");
  try {
    const payload = await apiRequest("/api/scan", {
      method: "POST",
      body: JSON.stringify({ config_id: configSelect.value }),
    });
    if (version !== workspaceVersion) return;
    displayFindings(payload.findings, configSelect.value);
    setStatus(scanStatus, `Scan complete: ${payload.scenario_id}.`);
  } catch (error) {
    if (version !== workspaceVersion) return;
    resultsSection.hidden = true;
    setStatus(scanStatus, error.message, true);
  } finally {
    if (version === workspaceVersion) scanButton.disabled = false;
  }
});

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const uploadedFile = configurationFileInput.files[0];
  if (!uploadedFile) {
    setStatus(uploadStatus, "Choose a JSON file before scanning.", true);
    return;
  }
  uploadButton.disabled = true;
  const version = workspaceVersion;
  resultsSection.hidden = true;
  setStatus(uploadStatus, "Validating your file and running the deterministic checks…");
  const body = new FormData();
  body.append("configuration_file", uploadedFile);
  try {
    const payload = await apiRequest("/api/scan-upload", { method: "POST", body });
    if (version !== workspaceVersion) return;
    displayFindings(payload.findings, "uploaded-file", uploadedFile);
    setStatus(
      uploadStatus,
      payload.findings.length
        ? `File scan complete: ${payload.scenario_id}.`
        : `Valid file scan complete: ${payload.scenario_id}; no findings.`,
    );
  } catch (error) {
    if (version !== workspaceVersion) return;
    resultsSection.hidden = true;
    setStatus(uploadStatus, error.message, true);
  } finally {
    if (version === workspaceVersion) uploadButton.disabled = false;
  }
});

customForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  let configuration;
  try {
    configuration = JSON.parse(customJsonInput.value);
  } catch {
    setStatus(customStatus, "Check the JSON syntax and try again.", true);
    customJsonInput.focus();
    return;
  }
  const editing = editingConfigurationId !== null;
  const version = workspaceVersion;
  const saveButtonText = saveCustomButton.textContent;
  saveCustomButton.disabled = true;
  setStatus(customStatus, editing ? "Saving your changes…" : "Saving your private example…");
  try {
    const endpoint = editing
      ? `/api/custom-configs/${encodeURIComponent(editingConfigurationId)}`
      : "/api/custom-configs";
    const payload = await apiRequest(endpoint, {
      method: editing ? "PUT" : "POST",
      body: JSON.stringify({ name: customNameInput.value, configuration }),
    });
    if (version !== workspaceVersion) return;
    setStatus(customStatus, editing ? "Your changes were saved." : "Your private example was saved.");
    resetCustomForm();
    await loadWorkspace();
    if (!editing) configSelect.value = payload.id;
  } catch (error) {
    if (version !== workspaceVersion) return;
    setStatus(customStatus, error.message, true);
  } finally {
    if (version === workspaceVersion) {
      saveCustomButton.disabled = false;
      if (editingConfigurationId === null) saveCustomButton.textContent = "Save private example";
      else saveCustomButton.textContent = saveButtonText;
    }
  }
});

cancelEditButton.addEventListener("click", () => {
  resetCustomForm();
  setStatus(customStatus, "Edit cancelled.");
});

async function initialize() {
  try {
    await refreshCsrfToken();
    const account = await apiRequest("/api/auth/me");
    if (account.authenticated) {
      showDashboard(account.user);
      return;
    }
    const requestedView = new URLSearchParams(window.location.search).get("view");
    if (requestedView === "signin" || requestedView === "signup") showAuth(requestedView);
    else showWelcome();
  } catch (error) {
    showAuth("signin");
    setAuthStatus("signin", error.message, true);
  }
}

void initialize();

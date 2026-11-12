"use strict";

const API = {
  health: "/api/health",
  status: "/api/status",
  policies: "/api/policies",
  scans: "/api/scans",
  inventoryScans: "/api/scans/inventory",
  findings: "/api/findings",
  comparisons: "/api/comparisons",
  assets: "/api/assets",
  scope: "/api/scope",
  openapi: "/api/openapi/specs",
  openapiMappings: "/api/openapi/mappings",
};

const PAGE_NAMES = {
  dashboard: "Dashboard",
  "new-scan": "New Scan",
  policies: "Policies",
  assets: "Asset Inventory",
  scope: "Authorization Scope",
  openapi: "OpenAPI",
  findings: "Findings",
  reports: "Reports",
  history: "History",
};

const PAGE_DESCRIPTIONS = {
  policies: "Review validated policies and their safe configuration metadata.",
  assets: "Register assets and record explicit authorization for future assessments.",
  scope: "Review included assets, exclusions, and current authorization eligibility.",
  openapi: "Browse supported operations from configured local OpenAPI documents.",
  findings: "Review authorization findings from completed scans.",
  reports: "Open JSON/HTML reports and compare completed scans against baselines.",
  history: "Browse persisted scans and inspect their findings and evidence.",
};

const elements = {
  sidebar: document.querySelector("#sidebar"),
  menuToggle: document.querySelector("#menu-toggle"),
  dashboardPage: document.querySelector("#dashboard-page"),
  newScanPage: document.querySelector("#new-scan-page"),
  workspacePage: document.querySelector("#workspace-page"),
  workspaceTitle: document.querySelector("#workspace-title"),
  workspaceDescription: document.querySelector("#workspace-description"),
  workspaceMessage: document.querySelector("#workspace-message"),
  workspaceContent: document.querySelector("#workspace-content"),
  workspaceRefresh: document.querySelector("#refresh-workspace"),
  pageName: document.querySelector("#page-name"),
  connectionStatus: document.querySelector("#connection-status"),
  connectionLabel: document.querySelector("#connection-label"),
  notice: document.querySelector("#api-notice"),
  noticeTitle: document.querySelector("#api-notice-title"),
  noticeMessage: document.querySelector("#api-notice-message"),
  totalScansStat: document.querySelector("#total-scans-stat"),
  completedScansStat: document.querySelector("#completed-scans-stat"),
  failedScansStat: document.querySelector("#failed-scans-stat"),
  findingsStat: document.querySelector("#findings-stat"),
  recentActivity: document.querySelector("#recent-activity"),
  versionStat: document.querySelector("#version-stat"),
  capabilityStat: document.querySelector("#capability-stat"),
  appVersion: document.querySelector("#app-version"),
  refreshButton: document.querySelector("#refresh-status"),
  scanForm: document.querySelector("#scan-form"),
  scanMode: document.querySelector("#scan-mode"),
  inventoryTargetControl: document.querySelector("#inventory-target-control"),
  inventoryTarget: document.querySelector("#inventory-target"),
  policySelect: document.querySelector("#policy-select"),
  openapiSelect: document.querySelector("#openapi-select"),
  valuesSelect: document.querySelector("#values-select"),
  policyHelp: document.querySelector("#policy-help"),
  policyReview: document.querySelector("#policy-review"),
  authorizationConfirmed: document.querySelector("#authorization-confirmed"),
  startScan: document.querySelector("#start-scan"),
  reloadPolicies: document.querySelector("#reload-policies"),
  scanMessage: document.querySelector("#scan-message"),
  scanResults: document.querySelector("#scan-results"),
  scanResultSummary: document.querySelector("#scan-result-summary"),
  scanResultData: document.querySelector("#scan-result-data"),
};

let policiesLoaded = false;
let openapiOptionsLoaded = false;
let inventoryExecutionEnabled = false;
let inventoryAssetsLoaded = false;
let scanRunning = false;
let activePage = "dashboard";
let scanPollTimer = null;
let statusRefreshInFlight = false;
let overviewLoaded = false;
let assetSearch = "";
let assetTypeFilter = "";
let assetStatusFilter = "";
let assetOffset = 0;

function navigate(page) {
  const selectedPage = PAGE_NAMES[page] ? page : "dashboard";
  const isDashboard = selectedPage === "dashboard";
  const isNewScan = selectedPage === "new-scan";
  const isWorkspacePage = [
    "policies", "assets", "scope", "openapi", "findings", "reports", "history",
  ].includes(selectedPage);

  if (!isNewScan) {
    inventoryAssetsLoaded = false;
  }
  elements.dashboardPage.hidden = !isDashboard;
  elements.newScanPage.hidden = !isNewScan;
  elements.workspacePage.hidden = !isWorkspacePage;
  activePage = selectedPage;
  elements.pageName.textContent = PAGE_NAMES[selectedPage];

  if (isWorkspacePage) {
    loadWorkspace(selectedPage);
  }

  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = link.dataset.page === selectedPage;
    link.classList.toggle("active", active);

    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });

  elements.sidebar.classList.remove("open");
  elements.menuToggle.setAttribute("aria-expanded", "false");

  if (isNewScan && !policiesLoaded) {
    loadPolicies();
  }
  if (isNewScan && !openapiOptionsLoaded) {
    loadOpenAPIOptions();
  }
  if (
    isNewScan &&
    inventoryExecutionEnabled &&
    elements.scanMode.value === "inventory" &&
    !inventoryAssetsLoaded
  ) {
    loadInventoryAssets();
  }
}

function setConnectionState(state, title, message) {
  const online = state === "online";
  const checking = state === "checking";

  elements.connectionStatus.classList.toggle("offline", !online && !checking);
  elements.connectionStatus.classList.toggle("checking", checking);
  elements.connectionLabel.textContent = checking
    ? "Checking API..."
    : online
      ? "API connected"
      : "API offline";

  elements.notice.classList.toggle("offline", !online && !checking);
  elements.noticeTitle.textContent = title;
  elements.noticeMessage.textContent = message;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
    cache: "no-store",
    credentials: "same-origin",
  });

  if (response.status === 204) {
    return null;
  }

  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error(`Backend returned an invalid response (HTTP ${response.status}).`);
  }

  if (!response.ok) {
    const message =
      typeof data.detail === "string"
        ? data.detail
        : typeof data.error === "string"
          ? data.error
          : `Backend returned HTTP ${response.status}.`;

    throw new Error(message);
  }

  return data;
}

async function refreshApiStatus(showChecking = false) {
  if (statusRefreshInFlight) {
    return;
  }
  statusRefreshInFlight = true;

  if (showChecking) {
    setConnectionState(
      "checking",
      "Connecting to local API",
      "Checking whether the AuthMatrix backend is available.",
    );
  }

  try {
    const [health, status] = await Promise.all([
      fetchJson(API.health),
      fetchJson(API.status),
    ]);

    const version = health.version || status.version || "Unknown";
    const capabilities = Array.isArray(status.capabilities)
      ? status.capabilities
      : [];
    inventoryExecutionEnabled =
      capabilities.includes("inventory_scoped_gui_execution");
    const inventoryMode = elements.scanMode.querySelector(
      'option[value="inventory"]',
    );
    inventoryMode.hidden = !inventoryExecutionEnabled;
    if (!inventoryExecutionEnabled && elements.scanMode.value === "inventory") {
      elements.scanMode.value = "loopback";
    }
    updateInventoryTargetControl();

    elements.versionStat.textContent = version;
    elements.appVersion.textContent = `v${version}`;
    elements.capabilityStat.textContent = String(capabilities.length);
    setConnectionState(
      "online",
      "AuthMatrix API is connected",
      `Backend is responding. ${capabilities.length} capabilities are available.`,
    );

    try {
      updateOverview(await fetchJson(API.scans));
    } catch (error) {
      if (!overviewLoaded) {
        showActivityError(`Could not load recent activity: ${error.message}`);
      }
    }
  } catch (error) {
    elements.versionStat.textContent = "—";
    elements.capabilityStat.textContent = "—";

    setConnectionState(
      "offline",
      "Cannot connect to the AuthMatrix API",
      `${error.message} Start the local AuthMatrix server and refresh this page.`,
    );
    if (!overviewLoaded) {
      showActivityError("Recent activity is unavailable while the API is offline.");
    }
  } finally {
    statusRefreshInFlight = false;
  }
}

function updateOverview(data) {
  const summary = data.summary || {};
  overviewLoaded = true;
  elements.totalScansStat.textContent = String(summary.total ?? 0);
  elements.completedScansStat.textContent = String(summary.completed ?? 0);
  elements.failedScansStat.textContent = String(summary.failed ?? 0);
  elements.findingsStat.textContent = String(summary.findings ?? 0);
  renderRecentActivity(Array.isArray(data.scans) ? data.scans.slice(0, 5) : []);
}

function renderRecentActivity(scans) {
  elements.recentActivity.replaceChildren();
  elements.recentActivity.setAttribute("aria-busy", "false");
  if (scans.length === 0) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No scans have been recorded yet.";
    elements.recentActivity.append(empty);
    return;
  }

  scans.forEach((scan) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    row.setAttribute("role", "listitem");

    const details = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = scan.policy || "Policy scan";
    const meta = document.createElement("p");
    meta.className = "activity-meta";
    meta.textContent = `${scan.status} · ${scan.generated_at || "time unavailable"} · ${scan.findings} finding(s)`;
    details.append(title, meta);

    const status = document.createElement("span");
    status.className = `status-pill ${scan.status}`;
    status.textContent = scan.status;
    row.append(details, status);
    elements.recentActivity.append(row);
  });
}

function showActivityError(message) {
  elements.recentActivity.replaceChildren();
  elements.recentActivity.setAttribute("aria-busy", "false");
  const error = document.createElement("p");
  error.className = "error-text";
  error.setAttribute("role", "status");
  error.textContent = message;
  elements.recentActivity.append(error);
}

function showWorkspaceMessage(message, type = "") {
  elements.workspaceMessage.textContent = message;
  elements.workspaceMessage.className = "scan-message";
  if (type) {
    elements.workspaceMessage.classList.add(type);
  }
  elements.workspaceMessage.hidden = false;
}

function createWorkspaceCard(titleText, detailsText = "") {
  const card = document.createElement("article");
  card.className = "workspace-card";
  const title = document.createElement("h2");
  title.textContent = titleText;
  card.append(title);
  if (detailsText) {
    const details = document.createElement("p");
    details.className = "activity-meta";
    details.textContent = detailsText;
    card.append(details);
  }
  return card;
}

async function loadWorkspace(page = activePage) {
  if (![
    "policies", "assets", "scope", "openapi", "findings", "reports", "history",
  ].includes(page)) {
    return;
  }

  elements.workspaceTitle.textContent = PAGE_NAMES[page];
  elements.workspaceDescription.textContent = PAGE_DESCRIPTIONS[page];
  elements.workspaceMessage.hidden = true;
  elements.workspaceContent.replaceChildren();
  elements.workspaceContent.textContent = "Loading...";

  try {
    if (page === "policies") {
      await renderPoliciesWorkspace();
    } else if (page === "assets") {
      await renderAssetsWorkspace();
    } else if (page === "scope") {
      await renderScopeWorkspace();
    } else if (page === "openapi") {
      await renderOpenApiWorkspace();
    } else if (page === "findings") {
      await renderFindingsWorkspace();
    } else {
      await renderScanWorkspace(page);
    }
  } catch (error) {
    elements.workspaceContent.replaceChildren();
    showWorkspaceMessage(error.message, "error");
  }
}

async function renderPoliciesWorkspace() {
  const data = await fetchJson(API.policies);
  elements.workspaceContent.replaceChildren();
  if (!Array.isArray(data.policies) || data.policies.length === 0) {
    elements.workspaceContent.textContent = "No valid policy files are available.";
    return;
  }

  for (const policy of data.policies) {
    const details = await fetchJson(`${API.policies}/${encodeURIComponent(policy)}`);
    const card = createWorkspaceCard(policy, `Authorized target: ${details.target}`);
    const identityList = document.createElement("p");
    identityList.textContent = `Identities: ${details.identities.map((identity) => `${identity.name} (${identity.role})`).join(", ")}`;
    const scope = document.createElement("p");
    scope.textContent = `Explicit authorization: ${details.authorized ? "confirmed in policy" : "missing"} · Allowed hosts: ${details.allowed_hosts.join(", ")} · Limit: ${details.max_requests} requests / ${details.max_response_bytes} response bytes`;
    const operations = document.createElement("ul");
    operations.className = "workspace-list";
    details.operations.forEach((operation) => {
      const item = document.createElement("li");
      item.textContent = `${operation.method} ${operation.path} · ${operation.category} · ${operation.id}`;
      operations.append(item);
    });
    card.append(identityList, scope, operations);
    elements.workspaceContent.append(card);
  }
}

function inventoryButton(label, action, className = "secondary-button") {
  const button = document.createElement("button");
  button.className = className;
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

function inventoryField(form, labelText, name, value = "", type = "text", required = false) {
  const field = document.createElement("div");
  field.className = "inventory-control";
  const label = document.createElement("label");
  const id = `asset-${name}`;
  label.htmlFor = id;
  label.textContent = labelText;
  const input = document.createElement("input");
  input.id = id;
  input.name = name;
  input.type = type;
  input.value = value || "";
  input.required = required;
  if (type === "text") {
    input.maxLength = name === "description" ? 2000 : 255;
  }
  field.append(label, input);
  form.append(field);
  return input;
}

function inventorySelect(form, labelText, name, options, selected = "") {
  const field = document.createElement("div");
  field.className = "inventory-control";
  const label = document.createElement("label");
  const id = `asset-${name}`;
  label.htmlFor = id;
  label.textContent = labelText;
  const select = document.createElement("select");
  select.id = id;
  select.name = name;
  options.forEach(([value, title]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = title;
    option.selected = value === selected;
    select.append(option);
  });
  field.append(label, select);
  form.append(field);
  return select;
}

const ASSET_TYPES = [
  ["domain", "Domain"],
  ["subdomain", "Subdomain"],
  ["hostname", "Hostname"],
  ["ipv4", "IPv4 address"],
  ["ipv6", "IPv6 address"],
  ["ipv4_cidr", "IPv4 CIDR"],
  ["ipv6_cidr", "IPv6 CIDR"],
];

function assetActions(asset) {
  const actions = document.createElement("div");
  actions.className = "inventory-actions";
  actions.append(
    inventoryButton("View", () => showAssetDetails(asset.asset_id)),
    inventoryButton("Edit", () => showAssetForm(asset)),
    inventoryButton("Authorization", () => showAuthorizationForm(asset)),
    inventoryButton(asset.active ? "Deactivate" : "Reactivate", async () => {
      try {
        await fetchJson(`${API.assets}/${encodeURIComponent(asset.asset_id)}/active`, {
          method: "PATCH",
          body: JSON.stringify({ active: !asset.active }),
        });
        await renderAssetsWorkspace();
        showWorkspaceMessage(`Asset ${asset.active ? "deactivated" : "reactivated"}.`, "success");
      } catch (error) {
        showWorkspaceMessage(error.message, "error");
      }
    }),
    inventoryButton("Delete", async () => {
      if (!window.confirm(`Delete asset "${asset.name}" and its scope entry?`)) {
        return;
      }
      try {
        await fetchJson(`${API.assets}/${encodeURIComponent(asset.asset_id)}`, {
          method: "DELETE",
        });
        await renderAssetsWorkspace();
        showWorkspaceMessage("Asset deleted.", "success");
      } catch (error) {
        showWorkspaceMessage(error.message, "error");
      }
    }),
  );
  if (asset.authorization_status !== "revoked") {
    actions.append(
      inventoryButton("Revoke authorization", async () => {
        if (!window.confirm(`Revoke authorization for "${asset.name}"?`)) {
          return;
        }
        try {
          await fetchJson(`${API.assets}/${encodeURIComponent(asset.asset_id)}/revoke`, {
            method: "POST",
          });
          await renderAssetsWorkspace();
          showWorkspaceMessage("Authorization revoked; this asset is no longer eligible.", "success");
        } catch (error) {
          showWorkspaceMessage(error.message, "error");
        }
      }),
    );
  }
  return actions;
}

async function renderAssetsWorkspace() {
  const params = new URLSearchParams({ limit: "100", offset: String(assetOffset) });
  if (assetSearch) params.set("search", assetSearch);
  if (assetTypeFilter) params.set("asset_type", assetTypeFilter);
  if (assetStatusFilter) params.set("authorization_status", assetStatusFilter);
  const data = await fetchJson(`${API.assets}?${params}`);
  elements.workspaceContent.replaceChildren();

  const summary = document.createElement("div");
  summary.className = "stats-grid inventory-stats";
  [
    ["Total assets", data.summary.total],
    ["Eligible", data.summary.authorized],
    ["Pending", data.summary.pending],
    ["Expired", data.summary.expired],
    ["Revoked", data.summary.revoked],
    ["Inactive", data.summary.inactive],
  ].forEach(([title, count]) => {
    const card = document.createElement("article");
    card.className = "stat-card";
    const label = document.createElement("div");
    label.className = "stat-top";
    label.textContent = title;
    const value = document.createElement("div");
    value.className = "stat-value";
    value.textContent = String(count);
    card.append(label, value);
    summary.append(card);
  });
  elements.workspaceContent.append(summary);

  const controls = document.createElement("section");
  controls.className = "panel inventory-toolbar";
  const searchForm = document.createElement("form");
  searchForm.className = "inventory-filters";
  const search = inventoryField(searchForm, "Search", "search", assetSearch);
  search.placeholder = "Name, value, description, or tag";
  search.setAttribute("aria-label", "Search assets");
  const type = inventorySelect(searchForm, "Asset type", "type", [
    ["", "All types"],
    ...ASSET_TYPES,
  ], assetTypeFilter);
  const status = inventorySelect(searchForm, "Authorization", "status", [
    ["", "All statuses"],
    ["authorized", "Authorized"],
    ["pending", "Pending"],
    ["expired", "Expired"],
    ["revoked", "Revoked"],
    ["unverified", "Unverified"],
  ], assetStatusFilter);
  const submit = document.createElement("button");
  submit.className = "secondary-button";
  submit.type = "submit";
  submit.textContent = "Search";
  searchForm.append(submit);
  searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    assetSearch = search.value;
    assetTypeFilter = type.value;
    assetStatusFilter = status.value;
    assetOffset = 0;
    await loadWorkspace("assets");
  });
  const add = inventoryButton("Add asset", () => showAssetForm(), "primary-button");
  controls.append(searchForm, add);
  elements.workspaceContent.append(controls);

  const assets = Array.isArray(data.assets) ? data.assets : [];
  if (assets.length === 0) {
    const empty = document.createElement("section");
    empty.className = "panel empty-state";
    empty.textContent = data.summary.total
      ? "No assets match these filters."
      : "No assets registered yet. Adding an asset does not authorize or scan it.";
    elements.workspaceContent.append(empty);
  } else {
    const tablePanel = document.createElement("section");
    tablePanel.className = "panel inventory-table-panel";
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    ["Asset", "Type", "Authorization", "Expiry", "State", "Created", "Actions"].forEach((text) => {
      const th = document.createElement("th");
      th.textContent = text;
      headerRow.append(th);
    });
    head.append(headerRow);
    const body = document.createElement("tbody");
    assets.forEach((asset) => {
      const row = document.createElement("tr");
      [
        `${asset.name}\n${asset.canonical_value}`,
        asset.asset_type,
        asset.authorization_status,
        asset.authorization_expires_at || "—",
        asset.active ? "Active" : "Inactive",
        new Date(asset.created_at).toLocaleDateString(),
      ].forEach((text, index) => {
        const cell = document.createElement("td");
        cell.textContent = text;
        if (index === 0) cell.className = "asset-name-cell";
        row.append(cell);
      });
      const actionCell = document.createElement("td");
      actionCell.append(assetActions(asset));
      row.append(actionCell);
      body.append(row);
    });
    table.append(head, body);
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.append(table);
    tablePanel.append(scroll);
    elements.workspaceContent.append(tablePanel);
  }

  const pagination = document.createElement("div");
  pagination.className = "inventory-pagination";
  const pageInfo = document.createElement("span");
  pageInfo.className = "muted";
  pageInfo.textContent = data.matching_total
    ? `Showing ${assetOffset + 1}–${assetOffset + assets.length} of ${data.matching_total} matching assets`
    : "No matching assets";
  const previous = inventoryButton("Previous", async () => {
    assetOffset = Math.max(0, assetOffset - 100);
    await loadWorkspace("assets");
  });
  previous.disabled = assetOffset === 0;
  const next = inventoryButton("Next", async () => {
    assetOffset += 100;
    await loadWorkspace("assets");
  });
  next.disabled = assetOffset + assets.length >= data.matching_total;
  pagination.append(pageInfo, previous, next);
  elements.workspaceContent.append(pagination);
}

function showAssetForm(asset = null) {
  const card = createWorkspaceCard(asset ? "Edit asset" : "Add an asset");
  const form = document.createElement("form");
  form.className = "inventory-form";
  inventoryField(form, "Asset name", "name", asset?.name || "", "text", true);
  inventorySelect(form, "Asset type", "asset_type", ASSET_TYPES, asset?.asset_type || "domain");
  inventoryField(form, "Asset value", "value", asset?.canonical_value || "", "text", true);
  const description = document.createElement("textarea");
  description.name = "description";
  description.id = "asset-description";
  description.maxLength = 2000;
  description.value = asset?.description || "";
  const descriptionLabel = document.createElement("label");
  descriptionLabel.htmlFor = description.id;
  descriptionLabel.textContent = "Description";
  form.append(descriptionLabel, description);
  inventoryField(form, "Tags (comma-separated)", "tags", asset?.tags?.join(", ") || "");
  inventoryField(form, "Organization / workspace", "organization", asset?.organization || "Local workspace");

  let confirmed = null;
  if (!asset) {
    confirmed = document.createElement("input");
    confirmed.type = "checkbox";
    confirmed.name = "authorization_confirmed";
    confirmed.id = "asset-authorization-confirmed";
    const label = document.createElement("label");
    label.className = "authorization-confirmation";
    label.htmlFor = confirmed.id;
    label.append(confirmed, document.createTextNode(" I explicitly confirm authorization for this asset."));
    form.append(label);
    inventoryField(form, "Authorization reference (required when confirmed)", "authorization_reference");
    inventoryField(form, "Authorization starts", "authorization_starts_at", "", "date");
    inventoryField(form, "Authorization expires", "authorization_expires_at", "", "date");
  }

  const actions = document.createElement("div");
  actions.className = "inventory-actions";
  const save = document.createElement("button");
  save.className = "primary-button";
  save.type = "submit";
  save.textContent = asset ? "Save changes" : "Create asset";
  actions.append(save, inventoryButton("Cancel", () => loadWorkspace("assets")));
  form.append(actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = new FormData(form);
    const payload = {
      name: values.get("name"),
      asset_type: values.get("asset_type"),
      value: values.get("value"),
      description: values.get("description"),
      tags: String(values.get("tags") || "").split(",").map((tag) => tag.trim()).filter(Boolean),
      organization: values.get("organization"),
    };
    if (!asset) {
      payload.authorization_confirmed = confirmed.checked;
      payload.authorization_reference = values.get("authorization_reference") || null;
      payload.authorization_starts_at = values.get("authorization_starts_at") || null;
      payload.authorization_expires_at = values.get("authorization_expires_at") || null;
    }
    save.disabled = true;
    save.textContent = "Saving...";
    try {
      const saved = await fetchJson(asset ? `${API.assets}/${encodeURIComponent(asset.asset_id)}` : API.assets, {
        method: asset ? "PUT" : "POST",
        body: JSON.stringify(payload),
      });
      await renderAssetsWorkspace();
      const targetChanged = asset && (
        asset.asset_type !== saved.asset_type ||
        asset.canonical_value !== saved.canonical_value
      );
      showWorkspaceMessage(
        targetChanged
          ? "Target changed; authorization was reset to pending and must be explicitly confirmed again."
          : asset
            ? "Asset updated."
            : "Asset created. Registration did not trigger a scan.",
        "success",
      );
    } catch (error) {
      save.disabled = false;
      save.textContent = asset ? "Save changes" : "Create asset";
      showWorkspaceMessage(error.message, "error");
    }
  });
  card.append(form);
  elements.workspaceContent.prepend(card);
  form.querySelector("input")?.focus();
}

function showAuthorizationForm(asset) {
  const card = createWorkspaceCard("Update authorization", asset.name);
  const form = document.createElement("form");
  form.className = "inventory-form";
  const status = inventorySelect(form, "Authorization status", "status", [
    ["pending", "Pending"],
    ["authorized", "Authorized"],
    ["unverified", "Unverified"],
  ], asset.authorization_status === "revoked" ? "pending" : asset.authorization_status);
  const confirmed = document.createElement("input");
  confirmed.type = "checkbox";
  confirmed.name = "authorization_confirmed";
  confirmed.id = "asset-authorization-confirmed";
  const confirmation = document.createElement("label");
  confirmation.className = "authorization-confirmation";
  confirmation.htmlFor = confirmed.id;
  confirmation.append(confirmed, document.createTextNode(" I explicitly confirm this authorization is valid."));
  form.append(confirmation);
  inventoryField(form, "Authorization reference", "authorization_reference", asset.authorization_reference || "");
  inventoryField(form, "Authorization starts", "authorization_starts_at", asset.authorization_starts_at || "", "date");
  inventoryField(form, "Authorization expires", "authorization_expires_at", asset.authorization_expires_at || "", "date");
  status.addEventListener("change", () => {
    if (status.value !== "authorized") confirmed.checked = false;
  });
  const save = document.createElement("button");
  save.className = "primary-button";
  save.type = "submit";
  save.textContent = "Save authorization";
  const actions = document.createElement("div");
  actions.className = "inventory-actions";
  actions.append(save, inventoryButton("Cancel", () => loadWorkspace("assets")));
  form.append(actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = new FormData(form);
    save.disabled = true;
    try {
      await fetchJson(`${API.assets}/${encodeURIComponent(asset.asset_id)}/authorization`, {
        method: "PUT",
        body: JSON.stringify({
          status: status.value,
          authorization_confirmed: confirmed.checked,
          authorization_reference: values.get("authorization_reference") || null,
          authorization_starts_at: values.get("authorization_starts_at") || null,
          authorization_expires_at: values.get("authorization_expires_at") || null,
        }),
      });
      await renderAssetsWorkspace();
      showWorkspaceMessage("Authorization record updated.", "success");
    } catch (error) {
      save.disabled = false;
      showWorkspaceMessage(error.message, "error");
    }
  });
  card.append(form);
  elements.workspaceContent.prepend(card);
  status.focus();
}

async function showAssetDetails(assetId) {
  try {
    const asset = await fetchJson(`${API.assets}/${encodeURIComponent(assetId)}`);
    const card = createWorkspaceCard(asset.name, asset.canonical_value);
    const details = document.createElement("dl");
    details.className = "asset-details";
    [
      ["Type", asset.asset_type],
      ["Description", asset.description || "—"],
      ["Tags", asset.tags.join(", ") || "—"],
      ["Organization", asset.organization],
      ["Authorization status", asset.authorization_status],
      ["Authorization confirmed", asset.authorization_confirmed ? "Yes" : "No"],
      ["Authorization reference", asset.authorization_reference || "—"],
      ["Authorization starts", asset.authorization_starts_at || "—"],
      ["Authorization expires", asset.authorization_expires_at || "No expiry recorded"],
      ["Active", asset.active ? "Yes" : "No"],
      ["Effective scope eligible", asset.effective_scope_eligible ? "Yes" : `No (${asset.eligibility_reason})`],
      ["Scope entry", asset.scope?.direction || "Not included or excluded"],
      ["Created", asset.created_at],
      ["Updated", asset.updated_at],
    ].forEach(([term, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = term;
      const dd = document.createElement("dd");
      dd.textContent = value;
      details.append(dt, dd);
    });
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "Current authorization metadata is retained; historical revisions are not currently stored.";
    card.append(details, note, assetActions(asset), inventoryButton("Back to assets", () => renderAssetsWorkspace()));
    elements.workspaceContent.replaceChildren(card);
  } catch (error) {
    showWorkspaceMessage(error.message, "error");
  }
}

async function renderScopeWorkspace() {
  const scope = await fetchJson(API.scope);
  elements.workspaceContent.replaceChildren();
  const notice = document.createElement("div");
  notice.className = "notice";
  notice.textContent = `${scope.message} Includes require active, current authorization. Exclusions override every inclusion, including parent domains and overlapping networks.`;
  elements.workspaceContent.append(notice);

  const summary = document.createElement("div");
  summary.className = "stats-grid inventory-stats";
  [
    ["Eligible includes", scope.eligible_count],
    ["Ineligible includes", scope.ineligible_count],
    ["Exclusions", scope.excluded.length],
  ].forEach(([title, count]) => {
    const card = document.createElement("article");
    card.className = "stat-card";
    const label = document.createElement("div");
    label.className = "stat-top";
    label.textContent = title;
    const value = document.createElement("div");
    value.className = "stat-value";
    value.textContent = String(count);
    card.append(label, value);
    summary.append(card);
  });
  elements.workspaceContent.append(summary);

  const addCard = createWorkspaceCard("Add a scope entry", "An asset may be explicitly included or excluded.");
  const addForm = document.createElement("form");
  addForm.className = "inventory-form";
  const assetFilter = inventoryField(addForm, "Find an asset", "asset_search");
  assetFilter.placeholder = "Search by name or canonical value";
  const assetSelect = inventorySelect(addForm, "Asset", "asset_id", []);
  const direction = inventorySelect(addForm, "Scope action", "direction", [
    ["include", "Include (requires authorization)"],
    ["exclude", "Exclude"],
  ]);
  async function loadScopeAssets(searchValue = "") {
    const params = new URLSearchParams({ limit: "100" });
    if (searchValue) params.set("search", searchValue);
    const result = await fetchJson(`${API.assets}?${params}`);
    assetSelect.replaceChildren();
    result.assets.forEach((asset) => {
      const option = document.createElement("option");
      option.value = asset.asset_id;
      option.textContent = `${asset.name} · ${asset.canonical_value} · ${asset.authorization_status}`;
      assetSelect.append(option);
    });
    assetSelect.disabled = result.assets.length === 0;
  }
  assetFilter.addEventListener("input", () => {
    window.clearTimeout(assetFilter.searchTimer);
    assetFilter.searchTimer = window.setTimeout(
      () => loadScopeAssets(assetFilter.value).catch((error) => showWorkspaceMessage(error.message, "error")),
      200,
    );
  });
  await loadScopeAssets();
  const addButton = document.createElement("button");
  addButton.className = "primary-button";
  addButton.type = "submit";
  addButton.textContent = "Save scope entry";
  addForm.append(addButton);
  addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addButton.disabled = true;
    try {
      await fetchJson(API.scope, {
        method: "POST",
        body: JSON.stringify({ asset_id: assetSelect.value, direction: direction.value }),
      });
      await renderScopeWorkspace();
      showWorkspaceMessage("Scope entry saved.", "success");
    } catch (error) {
      addButton.disabled = false;
      showWorkspaceMessage(error.message, "error");
    }
  });
  addCard.append(addForm);
  elements.workspaceContent.append(addCard);

  for (const [directionName, entries] of [
    ["Included assets", scope.included],
    ["Excluded assets", scope.excluded],
  ]) {
    const panel = createWorkspaceCard(directionName);
    if (entries.length === 0) {
      panel.append(Object.assign(document.createElement("p"), {
        className: "muted",
        textContent: "No entries.",
      }));
    }
    entries.forEach((entry) => {
      const row = document.createElement("div");
      row.className = "scope-entry";
      const detail = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = `${entry.name} · ${entry.value}`;
      const status = document.createElement("p");
      status.className = "activity-meta";
      status.textContent = directionName.startsWith("Included")
        ? `${entry.authorization_status} · ${entry.eligible ? "eligible" : `not eligible (${entry.eligibility_reason})`}`
        : "Excluded regardless of authorization state";
      detail.append(title, status);
      const remove = inventoryButton("Remove", async () => {
        try {
          await fetchJson(`${API.scope}/${encodeURIComponent(entry.asset_id)}`, { method: "DELETE" });
          await renderScopeWorkspace();
          showWorkspaceMessage("Scope entry removed.", "success");
        } catch (error) {
          showWorkspaceMessage(error.message, "error");
        }
      });
      row.append(detail, remove);
      panel.append(row);
    });
    elements.workspaceContent.append(panel);
  }

  const validate = createWorkspaceCard("Check a proposed target", "This validates registered scope only; it performs no network or DNS requests.");
  const validateForm = document.createElement("form");
  validateForm.className = "inventory-form";
  const targetType = inventorySelect(validateForm, "Target type", "target_type", ASSET_TYPES);
  const targetValue = inventoryField(validateForm, "Target value", "target_value", "", "text", true);
  const checkButton = document.createElement("button");
  checkButton.className = "secondary-button";
  checkButton.type = "submit";
  checkButton.textContent = "Validate target";
  const result = document.createElement("pre");
  result.className = "scope-result";
  result.setAttribute("role", "status");
  validateForm.append(checkButton);
  validateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    checkButton.disabled = true;
    result.textContent = "Checking registered scope...";
    try {
      const check = await fetchJson(`${API.scope}/validate`, {
        method: "POST",
        body: JSON.stringify({ asset_type: targetType.value, value: targetValue.value }),
      });
      result.textContent = `${check.eligible ? "ELIGIBLE" : "NOT ELIGIBLE"} · ${check.reason}\n${JSON.stringify(check, null, 2)}`;
    } catch (error) {
      result.textContent = `Validation failed: ${error.message}`;
    } finally {
      checkButton.disabled = false;
    }
  });
  validate.append(validateForm, result);
  elements.workspaceContent.append(validate);
}

async function renderOpenApiWorkspace() {
  const data = await fetchJson(API.openapi);
  const specifications = Array.isArray(data.specifications)
    ? data.specifications
    : [];
  elements.workspaceContent.replaceChildren();
  if (specifications.length === 0) {
    elements.workspaceContent.textContent =
      "No supported local OpenAPI documents are available in the configured directory.";
    return;
  }

  for (const specName of specifications) {
    const inventory = await fetchJson(
      `${API.openapi}/${encodeURIComponent(specName)}`,
    );
    const card = createWorkspaceCard(
      inventory.title || specName,
      `${specName} · OpenAPI ${inventory.openapi_version} · ${inventory.operations.length} operation(s)`,
    );
    const operations = document.createElement("ul");
    operations.className = "workspace-list";
    inventory.operations.forEach((operation) => {
      const item = document.createElement("li");
      item.textContent = `${operation.method} ${operation.path} · ${operation.operation_id || operation.summary || "operation"}`;
      const parameters = document.createElement("pre");
      parameters.textContent = JSON.stringify(operation.parameters, null, 2);
      item.append(parameters);
      operations.append(item);
    });
    card.append(operations);
    elements.workspaceContent.append(card);
  }
}

async function renderScanWorkspace(page) {
  const data = await fetchJson(API.scans);
  const scans = Array.isArray(data.scans) ? data.scans : [];
  elements.workspaceContent.replaceChildren();
  if (page === "reports") {
    elements.workspaceContent.append(createBaselineComparison(scans));
  }
  if (scans.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "No scans have been recorded yet.";
    elements.workspaceContent.append(empty);
    return;
  }

  scans.forEach((scan) => {
    const card = createWorkspaceCard(
      scan.policy || "Policy scan",
      `${scan.status} · ${scan.generated_at || "time unavailable"} · ${scan.requests} request(s) · ${scan.findings} finding(s)`,
    );
    if (page === "reports" && scan.status === "completed") {
      const jsonLink = document.createElement("a");
      jsonLink.href = `${API.scans}/${encodeURIComponent(scan.scan_id)}/report.json`;
      jsonLink.textContent = "JSON report";
      jsonLink.target = "_blank";
      jsonLink.rel = "noopener";
      const htmlLink = document.createElement("a");
      htmlLink.href = `${API.scans}/${encodeURIComponent(scan.scan_id)}/report.html`;
      htmlLink.textContent = "HTML report";
      htmlLink.target = "_blank";
      htmlLink.rel = "noopener";
      card.append(jsonLink, htmlLink);
    }
    if (page === "history") {
      const status = document.createElement("span");
      status.className = `status-pill ${scan.status}`;
      status.textContent = scan.status;
      card.append(status);
      if (scan.status === "completed") {
        const detailButton = document.createElement("button");
        detailButton.className = "text-button";
        detailButton.type = "button";
        detailButton.textContent = "Inspect findings and evidence";
        detailButton.addEventListener("click", () => showScanDetails(scan.scan_id));
        card.append(detailButton);
      }
    }
    elements.workspaceContent.append(card);
  });
}

function createBaselineComparison(scans) {
  const card = createWorkspaceCard(
    "Baseline comparison",
    "Compare two completed scans for the same target.",
  );
  const baseline = document.createElement("select");
  baseline.setAttribute("aria-label", "Baseline scan");
  const current = document.createElement("select");
  current.setAttribute("aria-label", "Current scan");
  [baseline, current].forEach((select, index) => {
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = index === 0 ? "Select baseline" : "Select current scan";
    select.append(placeholder);
  });
  scans.filter((scan) => scan.status === "completed").forEach((scan) => {
    [baseline, current].forEach((select) => {
      const option = document.createElement("option");
      option.value = scan.scan_id;
      option.textContent = `${scan.policy || "Policy"} · ${scan.generated_at}`;
      select.append(option);
    });
  });

  const button = document.createElement("button");
  button.className = "secondary-button";
  button.type = "button";
  button.textContent = "Compare scans";
  const result = document.createElement("p");
  result.className = "activity-meta";
  result.setAttribute("role", "status");
  const details = document.createElement("div");
  button.addEventListener("click", async () => {
    if (!baseline.value || !current.value) {
      result.textContent = "Select both a baseline and a current scan.";
      details.replaceChildren();
      return;
    }
    result.textContent = "Comparing scans...";
    details.replaceChildren();
    try {
      const comparison = await fetchJson(API.comparisons, {
        method: "POST",
        body: JSON.stringify({
          baseline_scan_id: baseline.value,
          current_scan_id: current.value,
        }),
      });
      result.textContent = [
        `New: ${comparison.summary.new}`,
        `Fixed: ${comparison.summary.fixed}`,
        `Recurring: ${comparison.summary.recurring}`,
      ].join(" · ");
      [
        ["New findings", comparison.new_findings],
        ["Fixed findings", comparison.fixed_findings],
        ["Recurring findings", comparison.recurring_findings],
      ].forEach(([titleText, findings]) => {
        const section = document.createElement("section");
        const heading = document.createElement("h3");
        heading.textContent = titleText;
        const list = document.createElement("ul");
        list.className = "workspace-list";
        if (findings.length === 0) {
          const item = document.createElement("li");
          item.textContent = "None";
          list.append(item);
        } else {
          findings.forEach((finding) => {
            const item = document.createElement("li");
            item.textContent = `${finding.severity} · ${finding.category} · ${finding.reproduction.method} ${finding.reproduction.path} · ${finding.reproduction.identity} · ${finding.title}`;
            list.append(item);
          });
        }
        section.append(heading, list);
        details.append(section);
      });
    } catch (error) {
      result.textContent = `Comparison failed: ${error.message}`;
    }
  });
  card.append(baseline, current, button, result, details);
  return card;
}

async function showScanDetails(scanId) {
  try {
    const scan = await fetchJson(`${API.scans}/${encodeURIComponent(scanId)}`);
    const card = createWorkspaceCard(
      `Scan ${scan.scan_id}`,
      `${scan.policy || "Policy"} · ${scan.target || "Target unavailable"} · ${scan.generated_at}`,
    );
    const summary = document.createElement("p");
    summary.textContent = `Requests: ${scan.summary.requests} · Passed: ${scan.summary.passed} · Failed: ${scan.summary.failed} · Inconclusive: ${scan.summary.inconclusive} · Skipped operations: ${scan.summary.skipped || 0} · Findings: ${scan.summary.findings}`;
    card.append(summary);
    const checks = Array.isArray(scan.checks) ? scan.checks : [];
    const reviewChecks = checks.filter(
      (check) => !check.passed || check.inconclusive,
    );
    const checkSummary = document.createElement("p");
    checkSummary.textContent = reviewChecks.length
      ? reviewChecks.map(formatCheck).join("\n")
      : "All checks matched their expected decisions.";
    card.append(checkSummary);
    const skipped = Array.isArray(scan.skipped_operations)
      ? scan.skipped_operations
      : [];
    if (skipped.length) {
      const skippedSummary = document.createElement("p");
      skippedSummary.textContent = `Skipped OpenAPI operations: ${skipped
        .map((item) => `${item.operation_id}: ${item.reason}`)
        .join("; ")}`;
      card.append(skippedSummary);
    }
    scan.findings.forEach((finding) => {
      const findingCard = document.createElement("section");
      const heading = document.createElement("h3");
      heading.textContent = `${finding.severity} · ${finding.category} · ${finding.title}`;
      const endpoint = document.createElement("p");
      endpoint.textContent = `${finding.reproduction.method} ${finding.reproduction.path} · identity ${finding.reproduction.identity}`;
      const evidence = document.createElement("pre");
      evidence.textContent = JSON.stringify(finding.evidence, null, 2);
      findingCard.append(heading, endpoint, evidence);
      card.append(findingCard);
    });
    elements.workspaceContent.prepend(card);
  } catch (error) {
    showWorkspaceMessage(error.message, "error");
  }
}

async function renderFindingsWorkspace() {
  const data = await fetchJson(API.findings);
  const findings = Array.isArray(data.findings) ? data.findings : [];
  elements.workspaceContent.replaceChildren();
  if (findings.length === 0) {
    elements.workspaceContent.textContent = "No findings are available.";
    return;
  }

  findings.forEach((finding) => {
    const card = createWorkspaceCard(
      finding.title || "Authorization finding",
      `${finding.severity || "unknown"} · ${finding.category || "unknown"} · ${finding.operation_id || "operation"} · ${finding.generated_at || ""}`,
    );
    const endpoint = document.createElement("p");
    endpoint.textContent = `${finding.reproduction.method} ${finding.reproduction.path} · identity ${finding.reproduction.identity} · resource ${finding.reproduction.resource_id || "n/a"}`;
    const evidence = document.createElement("pre");
    evidence.textContent = JSON.stringify(finding.evidence || {}, null, 2);
    const remediation = document.createElement("p");
    remediation.textContent = `Remediation: ${finding.remediation || "Review server-side authorization."}`;
    card.append(endpoint, evidence, remediation);
    elements.workspaceContent.append(card);
  });
}

function showScanMessage(message, type = "") {
  elements.scanMessage.textContent = message;
  elements.scanMessage.className = "scan-message";

  if (type) {
    elements.scanMessage.classList.add(type);
  }

  elements.scanMessage.hidden = false;
}

async function loadPolicies() {
  policiesLoaded = false;
  elements.authorizationConfirmed.checked = false;
  elements.policyReview.hidden = true;
  elements.policySelect.replaceChildren();

  const loadingOption = document.createElement("option");
  loadingOption.value = "";
  loadingOption.textContent = "Loading policies...";
  elements.policySelect.append(loadingOption);
  elements.policySelect.disabled = true;
  elements.startScan.disabled = true;
  elements.policyHelp.textContent = "Retrieving validated policy files...";

  try {
    const data = await fetchJson(API.policies);
    const policies = Array.isArray(data.policies) ? data.policies : [];

    elements.policySelect.replaceChildren();

    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = policies.length
      ? "Select an authorization policy"
      : "No valid policies found";
    elements.policySelect.append(defaultOption);

    policies.forEach((policy) => {
      if (
        typeof policy !== "string" ||
        !/^[a-zA-Z0-9._-]+\.ya?ml$/i.test(policy)
      ) {
        return;
      }

      const option = document.createElement("option");
      option.value = policy;
      option.textContent = policy;
      elements.policySelect.append(option);
    });

    const hasPolicies = elements.policySelect.options.length > 1;
    elements.policySelect.disabled = !hasPolicies;
    elements.startScan.disabled =
      !hasPolicies || scanRunning || !elements.authorizationConfirmed.checked;
    elements.policyHelp.textContent = hasPolicies
      ? `${elements.policySelect.options.length - 1} validated policy file(s) available.`
      : "Add a valid AuthMatrix YAML policy to your configured policy directory.";

    policiesLoaded = true;
  } catch (error) {
    elements.policySelect.replaceChildren();

    const errorOption = document.createElement("option");
    errorOption.value = "";
    errorOption.textContent = "Unable to load policies";
    elements.policySelect.append(errorOption);

    elements.policyHelp.textContent = error.message;
    showScanMessage(
      `Could not load policy files: ${error.message}`,
      "error",
    );
  }
}

function updateInventoryTargetControl() {
  const selected = inventoryExecutionEnabled &&
    elements.scanMode.value === "inventory";
  elements.inventoryTargetControl.hidden = !selected;
  elements.inventoryTarget.required = selected;
}

async function loadInventoryAssets() {
  elements.inventoryTarget.replaceChildren();
  const loading = document.createElement("option");
  loading.value = "";
  loading.textContent = "Loading authorized assets...";
  elements.inventoryTarget.append(loading);
  elements.inventoryTarget.disabled = true;
  updateStartButton();

  try {
    const assets = [];
    for (let offset = 0; offset < 5000; offset += 100) {
      const page = await fetchJson(`${API.assets}?limit=100&offset=${offset}`);
      const batch = Array.isArray(page.assets) ? page.assets : [];
      assets.push(...batch);
      if (batch.length < 100 || assets.length >= page.summary.total) {
        break;
      }
    }
    elements.inventoryTarget.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = assets.length
      ? "Select an authorized target asset"
      : "No authorized target assets available";
    elements.inventoryTarget.append(placeholder);
    assets
      .filter((asset) =>
        ["domain", "subdomain", "hostname", "ipv4", "ipv6"].includes(asset.asset_type) &&
        asset.authorization_status === "authorized" &&
        asset.active === true &&
        asset.scope_eligible === true
      )
      .forEach((asset) => {
        const option = document.createElement("option");
        option.value = asset.asset_id;
        option.textContent = `${asset.name} · ${asset.asset_type} · ${asset.canonical_value}`;
        elements.inventoryTarget.append(option);
      });
    inventoryAssetsLoaded = true;
    elements.inventoryTarget.disabled = elements.inventoryTarget.options.length <= 1;
    updateStartButton();
  } catch (error) {
    elements.inventoryTarget.replaceChildren();
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Unable to load authorized assets";
    elements.inventoryTarget.append(option);
    inventoryAssetsLoaded = false;
    updateStartButton();
    showScanMessage(`Could not load inventory assets: ${error.message}`, "error");
  }
}

async function loadOpenAPIOptions() {
  try {
    const [specData, mappingData] = await Promise.all([
      fetchJson(API.openapi),
      fetchJson(API.openapiMappings),
    ]);
    [
      {
        select: elements.openapiSelect,
        names: specData.specifications,
        placeholder: "Use policy-defined operations only",
        pattern: /^[a-zA-Z0-9._-]+\.json$/i,
      },
      {
        select: elements.valuesSelect,
        names: mappingData.mappings,
        placeholder: "Select a local mapping file",
        pattern: /^[a-zA-Z0-9._-]+\.ya?ml$/i,
      },
    ].forEach(({ select, names, placeholder, pattern }) => {
      select.replaceChildren();
      const option = document.createElement("option");
      option.value = "";
      option.textContent = placeholder;
      select.append(option);
      (Array.isArray(names) ? names : []).forEach((name) => {
        if (
          typeof name !== "string" ||
          !(pattern.test(name) || (select === elements.openapiSelect && /\.ya?ml$/i.test(name)))
        ) {
          return;
        }
        const available = document.createElement("option");
        available.value = name;
        available.textContent = name;
        select.append(available);
      });
    });
    openapiOptionsLoaded = true;
  } catch (error) {
    elements.openapiSelect.replaceChildren();
    elements.valuesSelect.replaceChildren();
    [
      [elements.openapiSelect, "OpenAPI documents unavailable"],
      [elements.valuesSelect, "Value mappings unavailable"],
    ].forEach(([select, message]) => {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = message;
      select.append(option);
    });
    showScanMessage(`Could not load OpenAPI scan options: ${error.message}`, "error");
  }
}

async function loadPolicyReview() {
  const policy = elements.policySelect.value;
  elements.policyReview.replaceChildren();
  elements.policyReview.hidden = !policy;
  if (!policy) {
    return;
  }

  try {
    const details = await fetchJson(
      `${API.policies}/${encodeURIComponent(policy)}`,
    );
    if (elements.policySelect.value !== policy) {
      return;
    }
    const resourceCount = details.resources.reduce(
      (count, resource) => count + resource.count,
      0,
    );
    const targetLine = elements.scanMode.value === "inventory"
      ? `Inventory target: ${elements.inventoryTarget.selectedOptions[0]?.textContent || "not selected"}`
      : `Target: ${details.target}`;
    elements.policyReview.textContent = [
      targetLine,
      ...(elements.scanMode.value === "inventory"
        ? [`Loopback policy template target: ${details.target}`]
        : []),
      `Policy authorization: ${details.authorized ? "authorized" : "not authorized"}`,
      `Authorized hosts: ${details.allowed_hosts.join(", ") || "none"}`,
      `Identities: ${details.identities.map((identity) => `${identity.name} (${identity.role})`).join(", ")}`,
      `Resources: ${details.resources.length} type(s), ${resourceCount} configured ID(s)`,
      `Operations:\n${details.operations.map((operation) => `${operation.id} (${operation.category}) · ${operation.method} ${operation.path}`).join("\n") || "None"}`,
      `Timeout: ${details.timeout_seconds}s · Max requests: ${details.max_requests}`,
      `Max response: ${details.max_response_bytes} bytes · Destructive methods: ${details.allow_destructive ? "enabled by policy" : "disabled"}`,
    ].join("\n");
  } catch (error) {
    if (elements.policySelect.value === policy) {
      elements.policyReview.textContent =
        `Policy details unavailable: ${error.message}`;
    }
  }
}

function renderScanResults(result) {
  const summary = result.summary || {};
  const metrics = [
    `Requests: ${summary.requests ?? 0}`,
    `Passed: ${summary.passed ?? 0}`,
    `Failed: ${summary.failed ?? 0}`,
    `Inconclusive: ${summary.inconclusive ?? 0}`,
    `Findings: ${summary.findings ?? 0}`,
    `Skipped operations: ${summary.skipped ?? 0}`,
  ];

  elements.scanResultSummary.textContent = metrics.join("  ·  ");

  const findings = Array.isArray(result.findings) ? result.findings : [];
  const checks = Array.isArray(result.checks) ? result.checks : [];
  const skipped = Array.isArray(result.skipped_operations)
    ? result.skipped_operations
    : [];

  elements.scanResultData.replaceChildren();

  const safeFindings = findings.map((finding, index) => ({
    number: index + 1,
    category:
      typeof finding.category === "string" ? finding.category : "Finding",
    severity:
      typeof finding.severity === "string" ? finding.severity : "Unknown",
    title:
      typeof finding.title === "string" ? finding.title : "Authorization issue",
    description:
      typeof finding.description === "string" ? finding.description : "",
    remediation:
      typeof finding.remediation === "string" ? finding.remediation : "",
    operation:
      typeof finding.reproduction?.method === "string" &&
      typeof finding.reproduction?.path === "string"
        ? `${finding.reproduction.method} ${finding.reproduction.path}`
        : "",
    evidence:
      finding.evidence && typeof finding.evidence === "object"
        ? JSON.stringify(finding.evidence)
        : "",
  }));

  const findingText = safeFindings.length
    ? safeFindings.map((finding) => {
        return [
          `${finding.number}. ${finding.title}`,
          `   Category: ${finding.category}`,
          `   Severity: ${finding.severity}`,
          finding.operation ? `   Operation: ${finding.operation}` : "",
          finding.evidence ? `   Evidence: ${finding.evidence}` : "",
          finding.description
            ? `   Description: ${finding.description}`
            : "",
          finding.remediation
            ? `   Remediation: ${finding.remediation}`
            : "",
        ]
          .filter(Boolean)
          .join("\n");
      })
        .join("\n\n")
    : "No confirmed authorization findings.";
  const reviewChecks = checks.filter(
    (check) => !check.passed || check.inconclusive,
  );
  const checkText = reviewChecks.length
    ? reviewChecks.map(formatCheck).join("\n")
    : "All checks matched their expected decisions.";
  const skippedText = skipped.length
    ? skipped.map((item) => `${item.operation_id}: ${item.reason}`).join("\n")
    : "None";
  elements.scanResultData.textContent =
    `${findingText}\n\nCheck outcomes:\n${checkText}\n\nSkipped OpenAPI operations:\n${skippedText}`;

  elements.scanResults.hidden = false;
}

function formatCheck(check) {
  const outcome = check.inconclusive ? "Inconclusive" : "Failed";
  return `${outcome}: ${check.category} ${check.method} ${check.path} · identity ${check.identity} · expected ${check.expected}, observed ${check.actual} · HTTP ${check.status_code}`;
}

async function startScan(event) {
  event.preventDefault();

  if (scanRunning) {
    return;
  }

  const policyPath = elements.policySelect.value;

  if (!policyPath) {
    showScanMessage("Select a policy before starting a scan.", "error");
    return;
  }
  const inventoryMode = elements.scanMode.value === "inventory";
  if (inventoryMode && !elements.inventoryTarget.value) {
    showScanMessage("Select an inventory asset before starting the scan.", "error");
    return;
  }
  if (Boolean(elements.openapiSelect.value) !== Boolean(elements.valuesSelect.value)) {
    showScanMessage(
      "Select both an OpenAPI document and a values mapping, or leave both blank.",
      "error",
    );
    return;
  }
  if (!elements.authorizationConfirmed.checked) {
    showScanMessage("Confirm that you are authorized to test this policy target.", "error");
    return;
  }

  scanRunning = true;
  elements.startScan.disabled = true;
  elements.reloadPolicies.disabled = true;
  elements.policySelect.disabled = true;
  elements.openapiSelect.disabled = true;
  elements.valuesSelect.disabled = true;
  elements.scanMode.disabled = true;
  elements.inventoryTarget.disabled = true;
  elements.authorizationConfirmed.disabled = true;
  elements.startScan.textContent = "Scan running...";
  elements.scanResults.hidden = true;

  showScanMessage(
    "Authorization scan started. The live status is shown below; request-level progress is not currently available.",
  );

  scanPollTimer = window.setInterval(pollScanState, 1000);
  try {
    const result = await fetchJson(
      inventoryMode ? API.inventoryScans : API.scans,
      {
        method: "POST",
        body: JSON.stringify({
          policy_path: policyPath,
          authorization_confirmed: elements.authorizationConfirmed.checked,
          ...(inventoryMode ? { asset_id: elements.inventoryTarget.value } : {}),
          ...(elements.openapiSelect.value
            ? {
                openapi_spec: elements.openapiSelect.value,
                values_mapping: elements.valuesSelect.value,
              }
            : {}),
        }),
      },
    );

    renderScanResults(result);
    await refreshApiStatus();

    const summary = result.summary || {};
    showScanMessage(
      `Scan ${result.status || "completed"}. ${summary.findings ?? 0} finding(s), ${summary.skipped ?? 0} OpenAPI operation(s) skipped.`,
      "success",
    );
  } catch (error) {
    showScanMessage(`Scan could not be completed: ${error.message}`, "error");
    await refreshApiStatus();
  } finally {
    window.clearInterval(scanPollTimer);
    scanPollTimer = null;
    scanRunning = false;
    elements.startScan.textContent = "Start authorization scan";
    elements.reloadPolicies.disabled = false;
    elements.policySelect.disabled =
      !policiesLoaded || elements.policySelect.options.length <= 1;
    elements.authorizationConfirmed.disabled = false;
    elements.openapiSelect.disabled = false;
    elements.valuesSelect.disabled = false;
    elements.scanMode.disabled = false;
    elements.inventoryTarget.disabled =
      !inventoryAssetsLoaded || elements.inventoryTarget.options.length <= 1;
    updateStartButton();
  }
}

function updateStartButton() {
  elements.startScan.disabled =
    scanRunning ||
    elements.policySelect.disabled ||
    !elements.policySelect.value ||
    (elements.scanMode.value === "inventory" &&
      (!inventoryExecutionEnabled || !elements.inventoryTarget.value)) ||
    !elements.authorizationConfirmed.checked;
}

async function pollScanState() {
  try {
    const data = await fetchJson(API.scans);
    updateOverview(data);
    const running = (data.scans || []).find((scan) => scan.status === "running");
    if (running) {
      showScanMessage(
        `Scan ${running.scan_id} is running under policy ${running.policy}. Request-level progress is unavailable.`,
      );
    }
  } catch {
    // The scan request itself reports the final API error.
  }
}

document.querySelectorAll("[data-page]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    const page = link.dataset.page;
    history.pushState({ page }, "", `#${page}`);
    navigate(page);
  });
});

window.addEventListener("popstate", () => {
  navigate(window.location.hash.slice(1) || "dashboard");
});

elements.menuToggle.addEventListener("click", () => {
  const isOpen = elements.sidebar.classList.toggle("open");
  elements.menuToggle.setAttribute("aria-expanded", String(isOpen));
});

elements.refreshButton.addEventListener("click", () => refreshApiStatus(true));
elements.workspaceRefresh.addEventListener("click", () => loadWorkspace());
elements.scanForm.addEventListener("submit", startScan);
elements.reloadPolicies.addEventListener("click", loadPolicies);
elements.scanMode.addEventListener("change", () => {
  elements.authorizationConfirmed.checked = false;
  updateInventoryTargetControl();
  elements.startScan.disabled = true;
  loadPolicyReview();
  if (
    elements.scanMode.value === "inventory" &&
    inventoryExecutionEnabled &&
    !inventoryAssetsLoaded
  ) {
    loadInventoryAssets();
  }
});
elements.inventoryTarget.addEventListener("change", () => {
  elements.authorizationConfirmed.checked = false;
  updateStartButton();
  loadPolicyReview();
});

elements.policySelect.addEventListener("change", () => {
  elements.authorizationConfirmed.checked = false;
  elements.startScan.disabled = true;
  loadPolicyReview();
});

[
  elements.openapiSelect,
  elements.valuesSelect,
].forEach((select) => {
  select.addEventListener("change", () => {
    elements.authorizationConfirmed.checked = false;
    elements.startScan.disabled = true;
  });
});

elements.authorizationConfirmed.addEventListener("change", () => {
  updateStartButton();
});

navigate(window.location.hash.slice(1) || "dashboard");
refreshApiStatus(true);
window.setInterval(refreshApiStatus, 5000);

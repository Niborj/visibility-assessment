const storageKey = "cato-ai-security-visibility-assessment";
const defaultEndpoint = "https://api.catonetworks.com/api/v1/graphql2";

const defaultApprovedApps = [
  "ChatGPT",
  "ChatGPT Personal (Paid)",
  "ChatGPT for Business",
  "Microsoft Copilot",
  "GitHub Copilot",
  "Claude",
  "Claude AI",
  "Gemini",
  "Perplexity",
  "Mistral",
  "Grok",
];

const defaultTrackedApps = [
  "ChatGPT",
  "OpenAI",
  "OpenAI API",
  "Claude",
  "Anthropic",
  "Anthropic API",
  "Claude Code",
  "Gemini",
  "Gemini API",
  "Google AI",
  "Microsoft Copilot",
  "Copilot",
  "GitHub Copilot",
  "Perplexity",
  "Mistral",
  "Mistral API",
  "Grok",
  "Azure OpenAI",
  "Amazon Bedrock",
  "Vertex AI",
  "OpenRouter",
  "Midjourney",
  "Character.AI",
  "Hugging Face",
  "Cursor",
];

const detectionEventSubtypes = ["Apps Security", "Saas Security API Data Protection"];

const aiNameExpressions = [
  /\bchatgpt\b/i,
  /\bopenai\b/i,
  /\banthropic\b/i,
  /\bclaude\b/i,
  /\bclaude code\b/i,
  /\bgemini\b/i,
  /\bgoogle ai\b/i,
  /\bperplexity\b/i,
  /\bmistral\b/i,
  /\bgrok\b/i,
  /\bcopilot\b/i,
  /\bgithub copilot\b/i,
  /\bcursor\b/i,
  /\bcodeium\b/i,
  /\bwindsurf\b/i,
  /\btabnine\b/i,
  /\bpoe\b/i,
  /\bdeepseek\b/i,
  /\bhugging ?face\b/i,
  /\bmidjourney\b/i,
  /\bcharacter\.?ai\b/i,
  /\bstable diffusion\b/i,
  /\bmeta ai\b/i,
  /\bbedrock\b/i,
  /\bvertex ai\b/i,
  /\bopenrouter\b/i,
  /\btogether ai\b/i,
  /\bcohere\b/i,
  /\belevenlabs\b/i,
  /\bsuno\b/i,
  /\bheygen\b/i,
  /\bsynthesia\b/i,
  /\bbolt\b/i,
  /\blovable\b/i,
  /\bv0\b/i,
  /\.ai\b/i,
];

const activityModeOrder = ["browser", "agentic", "proxy"];

const activityModeMeta = {
  browser: {
    label: "Web AI assistants",
    empty: "No web assistant activity detected",
  },
  agentic: {
    label: "Coding tools / agents",
    empty: "No coding tool or desktop-agent activity detected",
  },
  proxy: {
    label: "AI platforms / APIs",
    empty: "No AI platform or API activity detected",
  },
};

const appClassificationProfiles = [
  {
    family: "Claude Code",
    mode: "agentic",
    promptFocus: true,
    keywords: ["claude code", "claudecode"],
  },
  {
    family: "GitHub Copilot",
    mode: "agentic",
    promptFocus: true,
    keywords: ["github copilot"],
  },
  {
    family: "Cursor",
    mode: "agentic",
    promptFocus: false,
    keywords: ["cursor"],
  },
  {
    family: "OpenAI API",
    mode: "proxy",
    promptFocus: false,
    keywords: ["openai api", "openai platform", "api.openai"],
  },
  {
    family: "Anthropic API",
    mode: "proxy",
    promptFocus: false,
    keywords: ["anthropic api", "api.anthropic", "anthropic console"],
  },
  {
    family: "Azure OpenAI",
    mode: "proxy",
    promptFocus: false,
    keywords: ["azure openai"],
  },
  {
    family: "Amazon Bedrock",
    mode: "proxy",
    promptFocus: false,
    keywords: ["amazon bedrock", "bedrock"],
  },
  {
    family: "Vertex AI",
    mode: "proxy",
    promptFocus: false,
    keywords: ["vertex ai", "google vertex ai"],
  },
  {
    family: "Gemini API",
    mode: "proxy",
    promptFocus: false,
    keywords: ["gemini api", "google ai studio api"],
  },
  {
    family: "Mistral API",
    mode: "proxy",
    promptFocus: false,
    keywords: ["mistral api"],
  },
  {
    family: "OpenRouter",
    mode: "proxy",
    promptFocus: false,
    keywords: ["openrouter"],
  },
  {
    family: "ChatGPT",
    mode: "browser",
    promptFocus: true,
    keywords: ["chatgpt", "chat gpt"],
  },
  {
    family: "Claude",
    mode: "browser",
    promptFocus: true,
    keywords: ["claude ai", "claude"],
  },
  {
    family: "Gemini",
    mode: "browser",
    promptFocus: true,
    keywords: ["gemini", "google ai studio"],
  },
  {
    family: "Perplexity",
    mode: "browser",
    promptFocus: true,
    keywords: ["perplexity"],
  },
  {
    family: "Mistral",
    mode: "browser",
    promptFocus: true,
    keywords: ["mistral"],
  },
  {
    family: "Grok",
    mode: "browser",
    promptFocus: true,
    keywords: ["grok", "xai"],
  },
  {
    family: "Copilot",
    mode: "browser",
    promptFocus: true,
    keywords: ["microsoft copilot", "copilot for microsoft 365", "copilot"],
  },
];

const appQuery = `
  query AppStats(
    $accountID: ID!,
    $timeFrame: TimeFrame!,
    $measures: [Measure],
    $dimensions: [Dimension],
    $filters: [AppStatsFilter!],
    $sort: [AppStatsSort!],
    $limit: Int,
    $from: Int
  ) {
    appStats(
      accountID: $accountID,
      timeFrame: $timeFrame,
      measures: $measures,
      dimensions: $dimensions,
      filters: $filters,
      sort: $sort
    ) {
      from
      to
      records(limit: $limit, from: $from) {
        fieldsMap
      }
    }
  }
`;

const appTimeSeriesQuery = `
  query AppStatsTimeSeries(
    $accountID: ID!,
    $timeFrame: TimeFrame!,
    $measures: [Measure],
    $filters: [AppStatsFilter!],
    $buckets: Int!
  ) {
    appStatsTimeSeries(
      accountID: $accountID,
      timeFrame: $timeFrame,
      measures: $measures,
      filters: $filters
    ) {
      from
      to
      granularity
      timeseries(buckets: $buckets) {
        label
        data
        key {
          measureFieldName
        }
      }
    }
  }
`;

const snapshotQuery = `
  query AccountSnapshot($accountID: ID!) {
    accountSnapshot(accountID: $accountID) {
      timestamp
      sites {
        connectivityStatus
      }
      users {
        connectivityStatus
      }
    }
  }
`;

const eventsQuery = `
  query Events(
    $accountID: ID!,
    $timeFrame: TimeFrame!,
    $measures: [EventsMeasure],
    $dimensions: [EventsDimension],
    $filters: [EventsFilter!],
    $sort: [EventsSort!],
    $limit: Int,
    $from: Int
  ) {
    events(
      accountID: $accountID,
      timeFrame: $timeFrame,
      measures: $measures,
      dimensions: $dimensions,
      filters: $filters,
      sort: $sort
    ) {
      from
      to
      total
      records(limit: $limit, from: $from) {
        fieldsMap
      }
    }
  }
`;

const state = loadState();
let currentReport = null;
let isLoading = false;

const el = selectElements();

hydrateInputs();
bind();
renderDefaultState();
updateActionState();

function selectElements() {
  return {
    tabButtons: Array.from(document.querySelectorAll(".tab-button")),
    tabPanels: Array.from(document.querySelectorAll(".tab-panel")),
    accountLabel: q("#accountLabel"),
    accountId: q("#accountId"),
    apiPrefix: q("#apiPrefix"),
    apiKey: q("#apiKey"),
    startDate: q("#startDate"),
    endDate: q("#endDate"),
    anonymizeNames: q("#anonymizeNames"),
    includeDetectionSignals: q("#includeDetectionSignals"),
    approvedApps: q("#approvedApps"),
    trackedApps: q("#trackedApps"),
    executiveContext: q("#executiveContext"),
    loadButton: q("#loadButton"),
    printButton: q("#printButton"),
    exportButton: q("#exportButton"),
    resetButton: q("#resetButton"),
    copyNarrativeButton: q("#copyNarrativeButton"),
    copyPowerShellButton: q("#copyPowerShellButton"),
    powerShellCode: q("#powerShellCode"),
    endpointChip: q("#endpointChip"),
    captureChip: q("#captureChip"),
    scopeChip: q("#scopeChip"),
    pressureGauge: q("#pressureGauge"),
    pressureValue: q("#pressureValue"),
    pressureLabel: q("#pressureLabel"),
    statusBanner: q("#statusBanner"),
    headlineTitle: q("#headlineTitle"),
    headlineBody: q("#headlineBody"),
    timeframeValue: q("#timeframeValue"),
    topSignalValue: q("#topSignalValue"),
    shadowSignalValue: q("#shadowSignalValue"),
    executiveSummary: q("#executiveSummary"),
    insightList: q("#insightList"),
    aiAppsValue: q("#aiAppsValue"),
    aiAppsDetail: q("#aiAppsDetail"),
    aiUsersValue: q("#aiUsersValue"),
    aiUsersDetail: q("#aiUsersDetail"),
    aiFlowsValue: q("#aiFlowsValue"),
    aiFlowsDetail: q("#aiFlowsDetail"),
    aiTrafficValue: q("#aiTrafficValue"),
    aiTrafficDetail: q("#aiTrafficDetail"),
    shadowValue: q("#shadowValue"),
    shadowDetail: q("#shadowDetail"),
    promptToolsValue: q("#promptToolsValue"),
    promptToolsDetail: q("#promptToolsDetail"),
    agenticValue: q("#agenticValue"),
    agenticDetail: q("#agenticDetail"),
    proxyValue: q("#proxyValue"),
    proxyDetail: q("#proxyDetail"),
    activityChart: q("#activityChart"),
    activityChartMeta: q("#activityChartMeta"),
    signalBoardBadge: q("#signalBoardBadge"),
    modeDonut: q("#modeDonut"),
    modeDonutValue: q("#modeDonutValue"),
    modeDonutCaption: q("#modeDonutCaption"),
    editionStack: q("#editionStack"),
    editionLegend: q("#editionLegend"),
    promptTopicChips: q("#promptTopicChips"),
    promptIntentChips: q("#promptIntentChips"),
    modeBadge: q("#modeBadge"),
    browserModeValue: q("#browserModeValue"),
    agenticModeValue: q("#agenticModeValue"),
    proxyModeValue: q("#proxyModeValue"),
    modeDetectionValue: q("#modeDetectionValue"),
    activityModeNarrative: q("#activityModeNarrative"),
    activityModeTable: q("#activityModeTable"),
    topAppValue: q("#topAppValue"),
    topUserValue: q("#topUserValue"),
    topLocationValue: q("#topLocationValue"),
    policyValue: q("#policyValue"),
    exposureNarrative: q("#exposureNarrative"),
    valueProofList: q("#valueProofList"),
    appsSubtitle: q("#appsSubtitle"),
    topAppsTable: q("#topAppsTable"),
    shadowBadge: q("#shadowBadge"),
    shadowAppsTable: q("#shadowAppsTable"),
    userBadge: q("#userBadge"),
    topUsersTable: q("#topUsersTable"),
    locationBadge: q("#locationBadge"),
    topLocationsTable: q("#topLocationsTable"),
    topUsersCompactTable: q("#topUsersCompactTable"),
    topDevicesTable: q("#topDevicesTable"),
    promptBadge: q("#promptBadge"),
    promptVisibilityValue: q("#promptVisibilityValue"),
    promptSignalValue: q("#promptSignalValue"),
    promptThemeCountValue: q("#promptThemeCountValue"),
    promptIntentCountValue: q("#promptIntentCountValue"),
    promptSummary: q("#promptSummary"),
    promptTopicsTable: q("#promptTopicsTable"),
    promptIntentsTable: q("#promptIntentsTable"),
    detectionsBadge: q("#detectionsBadge"),
    detectionsTable: q("#detectionsTable"),
    reportNarrative: q("#reportNarrative"),
  };
}

function q(selector) {
  return document.querySelector(selector);
}

function buildDefaultState() {
  const end = new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - 29);

  return {
    activeTab: "configure",
    accountLabel: "",
    accountId: "",
    apiPrefix: "",
    apiKey: "",
    startDate: toInputDate(start),
    endDate: toInputDate(end),
    anonymizeNames: true,
    includeDetectionSignals: true,
    approvedApps: defaultApprovedApps.join("\n"),
    trackedApps: defaultTrackedApps.join("\n"),
    executiveContext: "",
  };
}

function loadState() {
  try {
    const base = buildDefaultState();
    const raw = localStorage.getItem(storageKey);
    return raw ? { ...base, ...JSON.parse(raw), apiKey: "" } : base;
  } catch {
    return buildDefaultState();
  }
}

function saveState() {
  const { apiKey, ...persisted } = state;
  localStorage.setItem(storageKey, JSON.stringify(persisted));
}

function hydrateInputs() {
  Object.keys(state).forEach((key) => {
    if (el[key]) {
      if (el[key].type === "checkbox") {
        el[key].checked = Boolean(state[key]);
      } else {
        el[key].value = state[key];
      }
    }
  });
  setActiveTab(state.activeTab, false);
  updateStaticChips();
  renderPowerShellSnippet();
}

function bind() {
  const textFields = [
    "accountLabel",
    "accountId",
    "apiPrefix",
    "apiKey",
    "startDate",
    "endDate",
    "approvedApps",
    "trackedApps",
    "executiveContext",
  ];

  textFields.forEach((key) => {
    el[key].addEventListener("input", (event) => {
      state[key] = event.target.value;
      saveState();
      updateStaticChips();
      renderPowerShellSnippet();
    });
  });

  ["anonymizeNames", "includeDetectionSignals"].forEach((key) => {
    el[key].addEventListener("change", (event) => {
      state[key] = event.target.checked;
      saveState();
      renderPowerShellSnippet();
      if (currentReport) {
        const nextConfig = {
          ...currentReport.config,
          anonymizeNames: state.anonymizeNames,
          includeDetectionSignals: state.includeDetectionSignals,
        };
        currentReport = buildReport({
          ...currentReport.sourceData,
          config: nextConfig,
        });
        renderReport(currentReport);
      }
    });
  });

  el.tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      setActiveTab(button.dataset.tabTarget || "configure");
    });
  });

  el.loadButton.addEventListener("click", runAssessment);
  el.printButton.addEventListener("click", () => {
    setActiveTab("report");
    window.print();
  });
  el.exportButton.addEventListener("click", exportReport);
  el.resetButton.addEventListener("click", resetState);
  el.copyNarrativeButton.addEventListener("click", copyNarrative);
  el.copyPowerShellButton.addEventListener("click", copyPowerShellStarter);
  window.addEventListener("beforeprint", () => setActiveTab("report"));
}

function setActiveTab(tab, persist = true) {
  const nextTab = tab === "report" ? "report" : "configure";
  state.activeTab = nextTab;

  el.tabButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.tabTarget === nextTab);
  });

  el.tabPanels.forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.tabPanel === nextTab);
  });

  if (persist) {
    saveState();
  }
}

function updateStaticChips() {
  el.endpointChip.textContent = computeEndpoint(state.apiPrefix);
  el.scopeChip.textContent = state.anonymizeNames ? "Customer export masked" : "Customer export named";
}

async function runAssessment() {
  if (isLoading) {
    return;
  }

  const validationError = validateInputs();
  if (validationError) {
    setStatus("risk", validationError);
    return;
  }

  isLoading = true;
  updateActionState();
  setStatus("neutral", "Pulling Cato analytics and building the executive report.");

  try {
    const config = buildConfig();
    const [appsResult, snapshotResult] = await Promise.allSettled([fetchApplications(config), fetchSnapshot(config)]);

    if (appsResult.status !== "fulfilled") {
      throw appsResult.reason;
    }

    const appBundle = appsResult.value;
    const aiApps = deriveAiApps(appBundle.records, config, appBundle.appField);

    const followUpFilterValues = unique(aiApps.map((item) => item.name));
    const secondary = await Promise.allSettled([
      fetchTimeSeries(config, appBundle.appField, followUpFilterValues),
      fetchUsers(config, appBundle.appField, followUpFilterValues),
      fetchDevices(config, appBundle.appField, followUpFilterValues),
      fetchSites(config, appBundle.appField, followUpFilterValues),
      fetchLocations(config, appBundle.appField, followUpFilterValues),
      state.includeDetectionSignals ? fetchDetections(config) : Promise.resolve(null),
    ]);

    const promptMetadata = state.includeDetectionSignals ? await fetchPromptMetadata(config) : null;

    const warnings = [];
    if (snapshotResult.status === "rejected") {
      warnings.push(`Snapshot query failed: ${snapshotResult.reason.message}`);
    }

    const [timeSeriesResult, usersResult, devicesResult, sitesResult, locationsResult, detectionsResult] = secondary;

    [timeSeriesResult, usersResult, devicesResult, sitesResult, locationsResult, detectionsResult].forEach((entry, index) => {
      if (entry.status === "rejected") {
        const labels = ["timeseries", "user", "device", "site", "location", "detection"];
        warnings.push(`${labels[index]} query failed: ${entry.reason.message}`);
      }
    });

    const report = buildReport({
      config,
      warnings,
      applicationField: appBundle.appField,
      apps: aiApps,
      allApps: appBundle.records,
      snapshot: snapshotResult.status === "fulfilled" ? snapshotResult.value : null,
      timeSeries: timeSeriesResult.status === "fulfilled" ? timeSeriesResult.value : null,
      users: usersResult.status === "fulfilled" ? usersResult.value : [],
      devices: devicesResult.status === "fulfilled" ? devicesResult.value : [],
      sites: sitesResult.status === "fulfilled" ? sitesResult.value : [],
      locations: locationsResult.status === "fulfilled" ? locationsResult.value : [],
      detections: detectionsResult.status === "fulfilled" ? detectionsResult.value : [],
      promptMetadata,
    });

    currentReport = report;
    renderReport(report);
    setActiveTab("report");

    const tone = report.warnings.length ? "warn" : "good";
    const message = report.warnings.length
      ? `Assessment loaded with partial warnings. ${report.warnings.length} section${report.warnings.length === 1 ? "" : "s"} returned limited data.`
      : "Assessment loaded successfully.";
    setStatus(tone, message);
  } catch (error) {
    currentReport = null;
    renderDefaultState();
    setStatus("risk", error.message || "Unable to load the assessment.");
  } finally {
    isLoading = false;
    updateActionState();
  }
}

function updateActionState() {
  el.loadButton.disabled = isLoading;
  el.resetButton.disabled = isLoading;
  el.printButton.disabled = isLoading || !currentReport;
  el.exportButton.disabled = isLoading || !currentReport;
  el.copyNarrativeButton.disabled = isLoading || !currentReport;
  el.loadButton.textContent = isLoading ? "Pulling..." : "Pull Assessment";
}

function validateInputs() {
  if (!state.accountId.trim()) {
    return "Add the CMA account ID before pulling the report.";
  }
  if (!state.apiKey.trim()) {
    return "Add the customer-specific read-only API key before pulling the report.";
  }
  if (!state.startDate || !state.endDate) {
    return "Choose both a start date and an end date.";
  }
  if (state.startDate > state.endDate) {
    return "The start date must be before the end date.";
  }
  return "";
}

function buildConfig() {
  return {
    accountLabel: state.accountLabel.trim() || `Account ${state.accountId.trim()}`,
    accountId: state.accountId.trim(),
    apiKey: state.apiKey.trim(),
    endpoint: computeEndpoint(state.apiPrefix),
    startDate: state.startDate,
    endDate: state.endDate,
    timeFrame: buildUtcTimeFrame(state.startDate, state.endDate),
    approvedApps: parseList(state.approvedApps),
    trackedApps: parseList(state.trackedApps),
    anonymizeNames: Boolean(state.anonymizeNames),
    includeDetectionSignals: Boolean(state.includeDetectionSignals),
    executiveContext: state.executiveContext.trim(),
  };
}

function computeEndpoint(rawPrefix) {
  const prefix = normalizePrefix(rawPrefix);
  return prefix ? `https://api.${prefix}.catonetworks.com/api/v1/graphql2` : defaultEndpoint;
}

function endpointCandidates(primary) {
  return unique([primary || defaultEndpoint, defaultEndpoint]);
}

function normalizePrefix(value) {
  const trimmed = String(value || "").trim().toLowerCase();
  if (!trimmed) {
    return "";
  }

  if (trimmed.includes("catonetworks.com")) {
    try {
      const url = new URL(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
      const host = url.hostname;
      if (host === "cc.catonetworks.com" || host === "api.catonetworks.com") {
        return "";
      }
      return host
        .replace(/^cc\./, "")
        .replace(/^api\./, "")
        .replace(/\.catonetworks\.com$/, "");
    } catch {
      return trimmed;
    }
  }

  return trimmed.replace(/^cc\./, "").replace(/^api\./, "").replace(/\.catonetworks\.com$/, "");
}

function buildUtcTimeFrame(startDate, endDate) {
  return `utc.{${startDate}/00:00:00--${endDate}/23:59:59}`;
}

function parseList(value) {
  return String(value || "")
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

async function fetchApplications(config) {
  const attempts = [
    buildApplicationAttempt("application", true),
    buildApplicationAttempt("application_name", true),
    buildApplicationAttempt("application", false),
    buildApplicationAttempt("application_name", false),
  ];

  return runAttemptSequence("application analytics", attempts, async (attempt) => {
    return {
      appField: attempt.appField,
      records: await fetchPagedApplicationRecords(config, attempt),
    };
  });
}

async function fetchPagedApplicationRecords(config, attempt) {
  const limit = 250;
  const records = [];

  for (let from = 0; from < 5000; from += limit) {
    const data = await graphqlRequest(
      appQuery,
      {
        accountID: config.accountId,
        timeFrame: config.timeFrame,
        dimensions: [{ fieldName: attempt.appField }],
        measures: attempt.measures,
        filters: [],
        sort: [{ fieldName: "traffic", order: "desc" }],
        limit,
        from,
      },
      config,
    );

    const page = (data.appStats?.records || []).map((record) => record.fieldsMap || {});
    records.push(...page);

    if (page.length < limit) {
      break;
    }
  }

  return records;
}

function buildApplicationAttempt(appField, includeMetadata) {
  const measures = [
    { fieldName: "traffic", aggType: "sum" },
    { fieldName: "flows_created", aggType: "sum" },
  ];

  if (includeMetadata) {
    measures.push(
      { fieldName: "risk_score", aggType: "max" },
      { fieldName: "risk_level", aggType: "any" },
      { fieldName: "sanctioned", aggType: "any" },
      { fieldName: "category", aggType: "any" },
    );
  }

  return { appField, measures };
}

async function fetchSnapshot(config) {
  const data = await graphqlRequest(snapshotQuery, { accountID: config.accountId }, config);
  return data.accountSnapshot || null;
}

async function fetchTimeSeries(config, appField, appNames) {
  if (!appNames.length) {
    return [];
  }

  const data = await graphqlRequest(
    appTimeSeriesQuery,
    {
      accountID: config.accountId,
      timeFrame: config.timeFrame,
      measures: [
        { fieldName: "flows_created", aggType: "sum" },
        { fieldName: "traffic", aggType: "sum" },
      ],
      filters: [{ fieldName: appField, operator: "in", values: appNames }],
      buckets: 10,
    },
    config,
  );

  return data.appStatsTimeSeries?.timeseries || [];
}

async function fetchUsers(config, appField, appNames) {
  if (!appNames.length) {
    return [];
  }

  const attempts = ["user_name", "user", "ad_name"].map((field) => ({ field }));
  return runAttemptSequence("user analytics", attempts, async (attempt) => {
    const data = await graphqlRequest(
      appQuery,
      {
        accountID: config.accountId,
        timeFrame: config.timeFrame,
        dimensions: [{ fieldName: attempt.field }],
        measures: [
          { fieldName: "traffic", aggType: "sum" },
          { fieldName: "flows_created", aggType: "sum" },
          { fieldName: appField, aggType: "count_distinct" },
        ],
        filters: [{ fieldName: appField, operator: "in", values: appNames }],
        sort: [{ fieldName: "traffic", order: "desc" }],
        limit: 12,
        from: 0,
      },
      config,
    );

    return (data.appStats?.records || []).map((record) => ({
      labelField: attempt.field,
      fieldsMap: record.fieldsMap || {},
    }));
  });
}

async function fetchDevices(config, appField, appNames) {
  if (!appNames.length) {
    return [];
  }

  const attempts = ["device_name", "host_name"].map((field) => ({ field }));
  return runAttemptSequence("device analytics", attempts, async (attempt) => {
    const data = await graphqlRequest(
      appQuery,
      {
        accountID: config.accountId,
        timeFrame: config.timeFrame,
        dimensions: [{ fieldName: attempt.field }],
        measures: [
          { fieldName: "traffic", aggType: "sum" },
          { fieldName: "flows_created", aggType: "sum" },
        ],
        filters: [{ fieldName: appField, operator: "in", values: appNames }],
        sort: [{ fieldName: "traffic", order: "desc" }],
        limit: 10,
        from: 0,
      },
      config,
    );

    return (data.appStats?.records || []).map((record) => ({
      labelField: attempt.field,
      fieldsMap: record.fieldsMap || {},
    }));
  });
}

async function fetchSites(config, appField, appNames) {
  if (!appNames.length) {
    return [];
  }

  const attempts = ["src_site_name", "site_name"].map((field) => ({ field }));
  return runAttemptSequence("site analytics", attempts, async (attempt) => {
    const data = await graphqlRequest(
      appQuery,
      {
        accountID: config.accountId,
        timeFrame: config.timeFrame,
        dimensions: [{ fieldName: attempt.field }],
        measures: [
          { fieldName: "traffic", aggType: "sum" },
          { fieldName: "flows_created", aggType: "sum" },
        ],
        filters: [{ fieldName: appField, operator: "in", values: appNames }],
        sort: [{ fieldName: "traffic", order: "desc" }],
        limit: 10,
        from: 0,
      },
      config,
    );

    return (data.appStats?.records || []).map((record) => ({
      labelField: attempt.field,
      fieldsMap: record.fieldsMap || {},
    }));
  });
}

async function fetchLocations(config, appField, appNames) {
  if (!appNames.length) {
    return [];
  }

  const attempts = [
    "site_country",
    "src_country_name",
    "country",
    "site_region",
    "site_state",
    "src_site_name",
    "site_name",
  ].map((field) => ({ field }));

  return runAttemptSequence("location analytics", attempts, async (attempt) => {
    const data = await graphqlRequest(
      appQuery,
      {
        accountID: config.accountId,
        timeFrame: config.timeFrame,
        dimensions: [{ fieldName: attempt.field }],
        measures: [
          { fieldName: "traffic", aggType: "sum" },
          { fieldName: "flows_created", aggType: "sum" },
        ],
        filters: [{ fieldName: appField, operator: "in", values: appNames }],
        sort: [{ fieldName: "traffic", order: "desc" }],
        limit: 10,
        from: 0,
      },
      config,
    );

    return (data.appStats?.records || []).map((record) => ({
      labelField: attempt.field,
      fieldsMap: record.fieldsMap || {},
    }));
  });
}

async function fetchDetections(config) {
  const data = await graphqlRequest(
    eventsQuery,
    {
      accountID: config.accountId,
      timeFrame: config.timeFrame,
      measures: [{ fieldName: "event_count", aggType: "sum" }],
      dimensions: [{ fieldName: "event_sub_type" }, { fieldName: "action" }],
      filters: [
        { fieldName: "event_type", operator: "is", values: ["Security"] },
        { fieldName: "event_sub_type", operator: "in", values: detectionEventSubtypes },
      ],
      sort: [{ fieldName: "event_count", order: "desc" }],
      limit: 12,
      from: 0,
    },
    config,
  );

  return (data.events?.records || []).map((record) => record.fieldsMap || {});
}

async function fetchPromptMetadata(config) {
  const attempts = [
    ["application", "topic", "intent", "detection_name", "action"],
    ["application_name", "topic", "intent", "detection_name", "action"],
    ["application", "topic", "intent", "action"],
    ["application_name", "topic", "intent", "action"],
    ["application", "topic", "detection_name", "action"],
    ["application_name", "topic", "detection_name", "action"],
    ["application", "intent", "detection_name", "action"],
    ["application_name", "intent", "detection_name", "action"],
    ["application", "topic", "action"],
    ["application_name", "topic", "action"],
    ["application", "intent", "action"],
    ["application_name", "intent", "action"],
    ["application", "action"],
    ["application_name", "action"],
  ];

  return runOptionalEventsDimensionQuery(config, attempts, 40);
}

async function runOptionalEventsDimensionQuery(config, dimensionSets, limit) {
  for (const dimensionFields of dimensionSets) {
    try {
      const data = await graphqlRequest(
        eventsQuery,
        {
          accountID: config.accountId,
          timeFrame: config.timeFrame,
          measures: [{ fieldName: "event_count", aggType: "sum" }],
          dimensions: dimensionFields.map((fieldName) => ({ fieldName })),
          filters: [
            { fieldName: "event_type", operator: "is", values: ["Security"] },
            { fieldName: "event_sub_type", operator: "in", values: detectionEventSubtypes },
          ],
          sort: [{ fieldName: "event_count", order: "desc" }],
          limit,
          from: 0,
        },
        config,
      );

      return {
        dimensionFields,
        records: (data.events?.records || []).map((record) => record.fieldsMap || {}),
      };
    } catch {}
  }

  return null;
}

async function graphqlRequest(query, variables, config) {
  const failures = [];

  for (const endpoint of endpointCandidates(config.endpoint)) {
    const response = await fetch("/api/graphql", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoint,
        apiKey: config.apiKey,
        query,
        variables,
      }),
    });

    const payload = await response.json().catch(() => ({}));
    if (response.ok && !payload.errors?.length) {
      config.endpoint = endpoint;
      return payload.data || {};
    }

    const message =
      payload.error || payload.errors?.map((item) => item.message).join(" ") || `Request failed with status ${response.status}.`;
    failures.push(`${endpoint}: ${message}`);
  }

  throw new Error(failures[failures.length - 1] || "Unable to reach the Cato GraphQL endpoint.");
}

async function runAttemptSequence(label, attempts, runner) {
  const failures = [];
  for (const attempt of attempts) {
    try {
      return await runner(attempt);
    } catch (error) {
      failures.push(error.message);
    }
  }
  throw new Error(`Unable to pull ${label}. ${failures[failures.length - 1] || "Unknown error."}`);
}

function classifyAiApp(name) {
  const raw = String(name || "").trim();
  const normalized = raw.toLowerCase();
  const profile = appClassificationProfiles.find((item) => item.keywords.some((keyword) => normalized.includes(keyword)));

  if (profile) {
    return {
      family: profile.family,
      mode: profile.mode,
      promptFocus: profile.promptFocus,
    };
  }

  if (/\b(api|platform|bedrock|vertex|openrouter)\b/.test(normalized)) {
    return {
      family: raw || "AI Proxy",
      mode: "proxy",
      promptFocus: false,
    };
  }

  if (/\b(code|cursor|ide|agent)\b/.test(normalized)) {
    return {
      family: raw || "Agentic tool",
      mode: "agentic",
      promptFocus: false,
    };
  }

  return {
    family: raw || "Browser AI",
    mode: "browser",
    promptFocus: false,
  };
}

function classifyPlanEdition(name, mode) {
  const normalized = String(name || "").trim().toLowerCase();

  if (mode === "proxy") {
    return "API / Platform";
  }

  if (!normalized) {
    return "Unspecified";
  }

  if (
    /\b(enterprise|business|team|workspace|organization|organisation|company|for microsoft 365|copilot for microsoft 365|edu|education)\b/.test(normalized)
  ) {
    return "Enterprise";
  }

  if (/\b(pro|plus|premium|advanced|paid|starter|individual)\b/.test(normalized)) {
    return "Paid";
  }

  if (/\b(free|basic|personal|community)\b/.test(normalized)) {
    return "Free";
  }

  return "Unspecified";
}

function matchesAiName(name) {
  const raw = String(name || "").trim();
  if (!raw) {
    return false;
  }

  return aiNameExpressions.some((expression) => expression.test(raw));
}

function isPromptFocusAppName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (classifyAiApp(name).promptFocus) {
    return true;
  }

  return /\b(openai|anthropic)\b/.test(normalized) && !/\b(api|platform|console)\b/.test(normalized);
}

function deriveAiApps(records, config, appField) {
  const approvedSet = new Set(config.approvedApps.map(normalize));
  const trackedPatterns = config.trackedApps.map((item) => item.toLowerCase());

  return records
    .map((fieldsMap) => {
      const rawName = fieldsMap[appField] || fieldsMap.application || fieldsMap.application_name || "Unknown app";
      const name = String(rawName).trim();
      const category = String(fieldsMap.category || "");
      const matched =
        matchesAiCategory(category) ||
        matchesAiName(name) ||
        trackedPatterns.some((pattern) => normalize(name).includes(normalize(pattern)));

      if (!matched) {
        return null;
      }

      const riskScore = toNumber(fieldsMap.risk_score);
      const sanctioned = parseBoolean(fieldsMap.sanctioned);
      const isApproved = approvedSet.has(normalize(name));
      const classification = classifyAiApp(name);

      return {
        name,
        family: classification.family,
        mode: classification.mode,
        edition: classifyPlanEdition(name, classification.mode),
        promptFocus: classification.promptFocus,
        traffic: toNumber(fieldsMap.traffic),
        flows: toNumber(fieldsMap.flows_created),
        riskScore,
        riskLevel: String(fieldsMap.risk_level || ""),
        category,
        sanctioned,
        approved: isApproved,
        shadow: !isApproved && sanctioned !== true,
      };
    })
    .filter(Boolean)
    .sort((left, right) => right.traffic - left.traffic);
}

function buildReport(input) {
  const apps = input.apps;
  const users = normalizeEntityRecords(input.users);
  const devices = normalizeEntityRecords(input.devices);
  const sites = normalizeEntityRecords(input.sites);
  const locations = normalizeEntityRecords(input.locations);
  const detections = input.config.includeDetectionSignals ? normalizeDetectionRecords(input.detections || []) : [];
  const policyActions = summarizePolicyActions(detections);
  const promptMetadata = input.config.includeDetectionSignals ? normalizePromptMetadata(input.promptMetadata) : [];
  const promptFocusMetadata = promptMetadata.filter((item) => isPromptFocusAppName(item.app));
  const totals = summarizeApps(apps);
  const planEditions = summarizePlanEditions(apps, totals);
  const meaningfulEditions = meaningfulPlanEditions(planEditions);
  const shadowApps = apps.filter((app) => app.shadow);
  const shadowTraffic = shadowApps.reduce((sum, item) => sum + item.traffic, 0);
  const shadowShare = totals.traffic ? shadowTraffic / totals.traffic : 0;
  const detectionCount = detections.reduce((sum, item) => sum + item.count, 0);
  const promptToolApps = unique(apps.filter((app) => app.promptFocus).map((app) => app.family));
  const activityModes = summarizeActivityModes(apps, totals, detectionCount);
  const governance = summarizeGovernance(apps, totals);
  const pressureIndex = calculatePressureIndex({
    apps: apps.length,
    users: users.length,
    flows: totals.flows,
    shadowShare,
    detections: detectionCount,
    avgRisk: totals.avgRisk,
  });

  const anonymizer = createAnonymizer();
  const topApp = apps[0] || null;
  const topUser = users[0] || null;
  const topLocation = locations[0] || null;
  const topSite = sites[0] || null;
  const snapshotText = buildSnapshotText(input.snapshot);
  const chart = normalizeSeries(input.timeSeries);
  const promptIntelligence = buildPromptIntelligence({
    apps,
    detections,
    promptMetadata: promptFocusMetadata,
  });
  const insights = buildInsights({
    config: input.config,
    apps,
    users,
    locations,
    shadowApps,
    shadowShare,
    detections,
    governance,
    policyActions,
    planEditions: meaningfulEditions,
    activityModes,
    promptIntelligence,
    warnings: input.warnings,
  });
  const headline = buildHeadline({
    apps,
    users,
    activityModes,
    shadowApps,
    shadowShare,
    detectionCount,
    governance,
    policyActions,
  });
  const reportText = buildNarrativeText({
    config: input.config,
    totals,
    apps,
    users,
    locations,
    shadowApps,
    shadowShare,
    detections,
    governance,
    policyActions,
    planEditions: meaningfulEditions,
    activityModes,
    promptIntelligence,
    snapshotText,
    warnings: input.warnings,
  });
  const valueProofs = buildValueProofs({
    apps,
    users,
    locations,
    governance,
    policyActions,
    activityModes,
    promptIntelligence,
  });

  return {
    ...input,
    sourceData: {
      config: input.config,
      warnings: input.warnings,
      applicationField: input.applicationField,
      apps: input.apps,
      allApps: input.allApps,
      snapshot: input.snapshot,
      timeSeries: input.timeSeries,
      users: input.users,
      devices: input.devices,
      sites: input.sites,
      locations: input.locations,
      detections: input.detections,
      promptMetadata: input.promptMetadata,
    },
    users,
    devices,
    sites,
    locations,
    detections,
    policyActions,
    promptMetadata,
    promptFocusMetadata,
    promptIntelligence,
    promptToolApps,
    planEditions,
    meaningfulEditions,
    totals,
    shadowApps,
    shadowShare,
    detectionCount,
    activityModes,
    governance,
    pressureIndex,
    anonymizer,
    topApp,
    topUser,
    topLocation,
    topSite,
    snapshotText,
    chart,
    insights,
    headline,
    valueProofs,
    reportText,
  };
}

function normalizeEntityRecords(records) {
  const grouped = new Map();

  records
    .map((entry) => {
      const keys = Object.keys(entry.fieldsMap || {});
      const labelKey = entry.labelField || keys.find((key) => !["traffic", "flows_created", "application", "application_name"].includes(key));
      const label = String(entry.fieldsMap?.[labelKey] || "").trim();
      if (!label) {
        return null;
      }
      const appCount =
        toNumber(entry.fieldsMap.application) ||
        toNumber(entry.fieldsMap.application_name) ||
        toNumber(entry.fieldsMap.app) ||
        0;

      return {
        label,
        dimension: labelKey,
        traffic: toNumber(entry.fieldsMap.traffic),
        flows: toNumber(entry.fieldsMap.flows_created),
        appCount,
      };
    })
    .filter(Boolean)
    .forEach((item) => {
      const key = normalize(item.label) || item.label.toLowerCase();
      if (!grouped.has(key)) {
        grouped.set(key, { ...item });
        return;
      }

      const existing = grouped.get(key);
      existing.traffic += item.traffic;
      existing.flows += item.flows;
      existing.appCount += item.appCount;
    });

  return Array.from(grouped.values()).sort((left, right) => right.traffic - left.traffic);
}

function normalizeDetectionRecords(records) {
  return records
    .map((fieldsMap) => ({
      subtype: String(fieldsMap.event_sub_type || "Detection"),
      action: String(fieldsMap.action || "Observed"),
      count: toNumber(fieldsMap.event_count),
    }))
    .filter((item) => item.count > 0)
    .sort((left, right) => right.count - left.count);
}

function summarizePolicyActions(detections) {
  const actionMap = new Map();
  const subtypeMap = new Map();

  detections.forEach((item) => {
    const actionKey = String(item.action || "Observed");
    const subtypeKey = String(item.subtype || "Detection");
    actionMap.set(actionKey, (actionMap.get(actionKey) || 0) + item.count);
    subtypeMap.set(subtypeKey, (subtypeMap.get(subtypeKey) || 0) + item.count);
  });

  const actions = Array.from(actionMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count);
  const subtypes = Array.from(subtypeMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count);
  const total = detections.reduce((sum, item) => sum + item.count, 0);
  const blocked = actions.find((item) => item.label.toLowerCase() === "block")?.count || 0;
  const allowed = actions.find((item) => item.label.toLowerCase() === "allow")?.count || 0;

  return {
    total,
    blocked,
    allowed,
    actions,
    subtypes,
    dominantAction: actions[0] || null,
    dominantSubtype: subtypes[0] || null,
  };
}

function normalizePromptMetadata(queryResult) {
  if (!queryResult?.records?.length) {
    return [];
  }

  return queryResult.records
    .map((fieldsMap) => {
      const record = normalizePromptRecord(fieldsMap);
      return {
        app: record.app,
        topic: record.topic,
        intent: record.intent,
        detection: record.detection,
        action: record.action,
        count: record.count,
      };
    })
    .filter((record) => record.count > 0 && (record.app || record.topic || record.intent || record.detection));
}

function normalizePromptRecord(fieldsMap) {
  return {
    app: pickField(fieldsMap, ["application", "application_name", "app"]),
    topic: pickField(fieldsMap, ["topic"]),
    intent: pickField(fieldsMap, ["intent"]),
    detection: pickField(fieldsMap, ["detection_name", "rule_name", "rule", "profile_name"]),
    action: pickField(fieldsMap, ["action"]) || "Observed",
    count: toNumber(fieldsMap.event_count),
  };
}

function buildPromptIntelligence({ apps, detections, promptMetadata }) {
  const themeMap = new Map();
  const topicMap = new Map();
  const intentMap = new Map();
  const promptToolApps = unique(apps.filter((app) => app.promptFocus).map((app) => app.family));
  const semanticMetadata = promptMetadata.filter((item) => item.topic || item.intent || item.detection);

  semanticMetadata.forEach((item) => {
    const label = promptThemeLabel(item) || "General AI prompting";
    const key = normalize(label) || label.toLowerCase();
    if (!themeMap.has(key)) {
      themeMap.set(key, {
        label,
        app: item.app || "Mixed AI apps",
        count: 0,
        action: item.action || "Observed",
      });
    }
    const theme = themeMap.get(key);
    theme.count += item.count;
    if (theme.app === "Mixed AI apps" && item.app) {
      theme.app = item.app;
    } else if (theme.app && item.app && theme.app !== item.app) {
      theme.app = "Mixed AI apps";
    }

    if (item.topic) {
      const topicKey = normalize(item.topic) || item.topic.toLowerCase();
      if (!topicMap.has(topicKey)) {
        topicMap.set(topicKey, {
          label: titleCase(item.topic),
          count: 0,
          app: item.app || "Mixed AI apps",
        });
      }
      const topicEntry = topicMap.get(topicKey);
      topicEntry.count += item.count;
      if (topicEntry.app && item.app && topicEntry.app !== item.app) {
        topicEntry.app = "Mixed AI apps";
      }
    }

    if (item.intent) {
      const intentKey = normalize(item.intent) || item.intent.toLowerCase();
      if (!intentMap.has(intentKey)) {
        intentMap.set(intentKey, {
          label: titleCase(item.intent),
          count: 0,
          app: item.app || "Mixed AI apps",
        });
      }
      const intentEntry = intentMap.get(intentKey);
      intentEntry.count += item.count;
      if (intentEntry.app && item.app && intentEntry.app !== item.app) {
        intentEntry.app = "Mixed AI apps";
      }
    }
  });

  const themes = Array.from(themeMap.values())
    .sort((left, right) => right.count - left.count)
    .slice(0, 8);
  const topics = Array.from(topicMap.values())
    .sort((left, right) => right.count - left.count)
    .slice(0, 8);
  const intents = Array.from(intentMap.values())
    .sort((left, right) => right.count - left.count)
    .slice(0, 8);

  const actionCounts = buildActionCounts(promptMetadata, detections);
  const dominantAction = actionCounts[0] || null;
  const policySignalCount = detections.reduce((sum, item) => sum + item.count, 0);
  const hasSemanticDetail = topics.length > 0 || intents.length > 0 || themes.length > 0;
  const visibility = hasSemanticDetail
    ? "Topic / intent available"
    : actionCounts.length
      ? "Action-level policy signals only"
      : "Prompt details not exposed";

  const dominantSignal =
    themes[0]?.label ||
    topics[0]?.label ||
    intents[0]?.label ||
    (dominantAction ? `${dominantAction.label} actions` : promptToolApps[0] ? `${promptToolApps[0]} activity` : "No prompt signals");
  const coverageText = promptToolApps.length
    ? `${promptToolApps.length} selected prompt tool${promptToolApps.length === 1 ? "" : "s"} detected`
    : apps.length
      ? "No selected prompt tools detected in AI activity"
      : "No AI apps detected";

  const tone = hasSemanticDetail ? "good" : actionCounts.length ? "warn" : "neutral";
  const summary = hasSemanticDetail
    ? "The account is exposing prompt-related metadata such as topic, intent, and policy match information for the selected assistant apps. Raw prompt text is not available through this API path."
    : actionCounts.length
      ? "The public API returned action-level policy evidence for AI interactions, but it did not return topic or intent detail for the selected assistant apps in this timeframe."
      : "The current API view did not expose prompt-level topic or intent metadata for the selected assistant apps in this timeframe.";

  return {
    visibility,
    tone,
    hasSemanticDetail,
    dominantSignal,
    coverageText,
    dominantAction: dominantAction ? `${dominantAction.label} (${formatNumber(dominantAction.count)})` : "No prompting actions returned",
    policySignalCount,
    focusApps: promptToolApps,
    themes,
    topics,
    intents,
    summary,
  };
}

function buildActionCounts(promptMetadata, detections) {
  const counts = new Map();
  const add = (label, count) => {
    const key = label || "Observed";
    counts.set(key, (counts.get(key) || 0) + count);
  };

  promptMetadata.forEach((item) => add(item.action || "Observed", item.count));
  if (!promptMetadata.length) {
    detections.forEach((item) => add(item.action || "Observed", item.count));
  }

  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count);
}

function promptThemeLabel(item) {
  if (item.topic && item.intent) {
    return `${titleCase(item.intent)} in ${titleCase(item.topic)}`;
  }
  if (item.topic) {
    return titleCase(item.topic);
  }
  if (item.intent) {
    return titleCase(item.intent);
  }
  if (item.detection) {
    return titleCase(item.detection);
  }
  if (item.app) {
    return `${item.app} interactions`;
  }
  return "";
}

function matchesAiCategory(category) {
  const text = String(category || "").trim().toLowerCase();
  return (
    text.includes("generative") ||
    text.includes("artificial intelligence") ||
    text.includes("machine learning") ||
    text.includes("assistant") ||
    text.includes("chatbot") ||
    text.includes("llm") ||
    /\bai\b/.test(text)
  );
}

function summarizeApps(apps) {
  const traffic = apps.reduce((sum, item) => sum + item.traffic, 0);
  const flows = apps.reduce((sum, item) => sum + item.flows, 0);
  const riskScores = apps.map((item) => item.riskScore).filter((value) => value > 0);
  return {
    traffic,
    flows,
    avgRisk: riskScores.length ? riskScores.reduce((sum, value) => sum + value, 0) / riskScores.length : 0,
  };
}

function summarizePlanEditions(apps, totals) {
  const buckets = new Map();

  apps.forEach((app) => {
    const key = app.edition || "Unspecified";
    if (!buckets.has(key)) {
      buckets.set(key, {
        edition: key,
        apps: 0,
        traffic: 0,
        flows: 0,
      });
    }

    const bucket = buckets.get(key);
    bucket.apps += 1;
    bucket.traffic += app.traffic;
    bucket.flows += app.flows;
  });

  return Array.from(buckets.values())
    .map((item) => ({
      ...item,
      share: totals.traffic ? item.traffic / totals.traffic : 0,
    }))
    .sort((left, right) => right.traffic - left.traffic);
}

function meaningfulPlanEditions(planEditions) {
  return (planEditions || []).filter((item) => item.edition && item.edition !== "Unspecified");
}

function summarizeGovernance(apps, totals) {
  const approvedApps = apps.filter((app) => app.approved);
  const sanctionedApps = apps.filter((app) => !app.approved && app.sanctioned === true);
  const reviewApps = apps.filter((app) => !app.approved && app.sanctioned !== true);

  const summarizeBucket = (items) => {
    const traffic = items.reduce((sum, item) => sum + item.traffic, 0);
    return {
      count: items.length,
      traffic,
      share: totals.traffic ? traffic / totals.traffic : 0,
    };
  };

  const approved = summarizeBucket(approvedApps);
  const sanctioned = summarizeBucket(sanctionedApps);
  const review = summarizeBucket(reviewApps);

  return {
    approved,
    sanctioned,
    review,
    approvedApps,
    sanctionedApps,
    reviewApps,
    governedCount: approved.count + sanctioned.count,
    governedShare: approved.share + sanctioned.share,
  };
}

function summarizeActivityModes(apps, totals, detectionCount) {
  const shareBase = totals.traffic > 0 ? totals.traffic : totals.flows;
  const buckets = new Map(
    activityModeOrder.map((mode) => [
      mode,
      {
        mode,
        label: activityModeMeta[mode].label,
        traffic: 0,
        flows: 0,
        apps: [],
      },
    ]),
  );

  apps.forEach((app) => {
    const bucket = buckets.get(app.mode || "browser") || buckets.get("browser");
    bucket.traffic += app.traffic;
    bucket.flows += app.flows;
    bucket.apps.push(app);
  });

  const items = activityModeOrder.map((mode) => {
    const bucket = buckets.get(mode);
    const topApp = bucket.apps.sort((left, right) => right.traffic - left.traffic)[0] || null;
    return {
      mode,
      label: bucket.label,
      traffic: bucket.traffic,
      flows: bucket.flows,
      share: shareBase ? (totals.traffic > 0 ? bucket.traffic / totals.traffic : bucket.flows / totals.flows) : 0,
      appCount: bucket.apps.length,
      topApp,
      leadingApps: bucket.apps.slice(0, 3).map((app) => app.name),
    };
  });

  const activeItems = items.filter((item) => item.traffic > 0 || item.flows > 0);
  const dominant = activeItems[0] ? activeItems.slice().sort((left, right) => right.traffic - left.traffic)[0] : null;
  const summary = activeItems.length
    ? `${dominant.label} currently account for the largest visible share of AI traffic at ${formatPercent(dominant.share)}. ${formatNumber(detectionCount)} security signal${detectionCount === 1 ? "" : "s"} ${detectionCount === 1 ? "was" : "were"} returned overall.`
    : "No web-assistant, coding-tool, or AI-platform activity was returned in the current dataset.";

  return {
    items,
    dominant,
    summary,
  };
}

function calculatePressureIndex({ apps, users, flows, shadowShare, detections, avgRisk }) {
  const appFactor = Math.min(apps * 7, 28);
  const userFactor = Math.min(users * 3.5, 24);
  const flowFactor = Math.min(Math.log10(flows + 1) * 14, 22);
  const shadowFactor = shadowShare * 22;
  const detectionFactor = detections > 0 ? Math.min(16, Math.log10(detections + 1) * 10) : 0;
  const riskFactor = Math.min(avgRisk * 1.2, 12);
  return Math.max(0, Math.min(100, Math.round(appFactor + userFactor + flowFactor + shadowFactor + detectionFactor + riskFactor)));
}

function buildSnapshotText(snapshot) {
  if (!snapshot) {
    return "Snapshot unavailable";
  }

  const connectedUsers = (snapshot.users || []).filter((user) => user.connectivityStatus === "connected").length;
  const connectedSites = (snapshot.sites || []).filter((site) => site.connectivityStatus === "connected").length;
  return `${connectedUsers} connected users, ${connectedSites} connected sites`;
}

function normalizeSeries(series) {
  const flows = series.find((entry) => entry.key?.measureFieldName === "flows_created");
  const traffic = series.find((entry) => entry.key?.measureFieldName === "traffic");

  const timestamps = new Set();
  [flows, traffic].forEach((entry) => {
    (entry?.data || []).forEach(([timestamp]) => timestamps.add(timestamp));
  });

  const ordered = Array.from(timestamps).sort((left, right) => left - right);
  return ordered.map((timestamp) => ({
    timestamp,
    flows: lookupSeriesValue(flows?.data, timestamp),
    traffic: lookupSeriesValue(traffic?.data, timestamp),
  }));
}

function lookupSeriesValue(series, timestamp) {
  if (!Array.isArray(series)) {
    return 0;
  }
  const match = series.find((point) => point[0] === timestamp);
  return match ? Number(match[1]) : 0;
}

function buildInsights({ config, apps, users, locations, shadowApps, shadowShare, detections, governance, policyActions, planEditions, activityModes, promptIntelligence, warnings }) {
  const items = [];

  if (!apps.length) {
    items.push("No tracked AI application activity matched the current app-detection list in the selected timeframe.");
  } else {
    items.push(`${apps.length} AI applications were detected, with ${users.length || "limited"} visible active users in the report.`);
  }

  const activeModes = activityModes.items.filter((item) => item.share > 0);
  if (activeModes.length) {
    items.push(
      activeModes
        .map((item) => `${item.label} accounts for ${formatPercent(item.share)} of AI traffic`)
        .join(", "),
    );
  }

  if (planEditions.length) {
    items.push(
      planEditions
        .slice(0, 3)
        .map((item) => `${item.edition} variants account for ${formatPercent(item.share)}`)
        .join(", "),
    );
  }

  if (locations.length) {
    items.push(`The strongest visible access location was ${describeLocationForNarrative(config, locations[0])}, which gives the CISO a concrete geography anchor for the assessment story.`);
  } else {
    items.push("Location-level visibility was limited in the current query set, so access geography may need a different dimension in the tenant.");
  }

  if (governance.review.count) {
    items.push(`${governance.review.count} visible AI application${governance.review.count === 1 ? "" : "s"} fell outside the approved or explicitly sanctioned set, representing ${formatPercent(governance.review.share)} of measured AI traffic.`);
  } else if (shadowApps.length) {
    items.push(`${shadowApps.length} AI application${shadowApps.length === 1 ? "" : "s"} fell outside the approved list, representing ${formatPercent(shadowShare)} of measured AI traffic.`);
  } else {
    items.push("No shadow AI was identified from the current approved-app list and sanctioning signals.");
  }

  if (!config.includeDetectionSignals) {
    items.push("Optional prompt and policy queries were not enabled for this run, so the report is centered on usage visibility rather than detection evidence.");
  } else if (policyActions.total) {
    items.push(`Cato returned ${formatNumber(policyActions.total)} AI security action${policyActions.total === 1 ? "" : "s"}, including ${formatNumber(policyActions.blocked)} blocked and ${formatNumber(policyActions.allowed)} allowed decisions, which is strong evidence of live governance rather than passive visibility.`);
  } else if (detections.length) {
    items.push(`${detections.length} detection pattern${detections.length === 1 ? "" : "s"} appeared in the security-events query, which suggests the account is surfacing policy-level AI or data-protection signals.`);
  } else {
    items.push("Prompt or policy-level detections were not returned by the optional security-events query for this timeframe.");
  }

  if (!config.includeDetectionSignals) {
    items.push("Prompt intelligence was not populated because the optional prompt and detection queries were disabled for this run.");
  } else if (promptIntelligence.hasSemanticDetail) {
    items.push(`Prompt intelligence is materially useful here: the account exposed topic and intent metadata in addition to policy signals.`);
  } else if (policyActions.total) {
    items.push("The public API did not return topic or intent metadata in this timeframe, but it did return action-level AI security evidence that is still highly relevant for executive reporting.");
  } else if (promptIntelligence.themes.length) {
    items.push(`Prompt intelligence is partially available: the account exposed prompt themes or intent-level metadata, but not raw prompt text.`);
  } else {
    items.push("Prompt intelligence is currently signal-only for the selected assistant apps, so customer-facing discussions should focus on governance patterns rather than quoting prompt text.");
  }

  if (warnings.length) {
    items.push(`${warnings.length} section${warnings.length === 1 ? "" : "s"} returned limited data, so this report should be positioned as directional rather than exhaustive.`);
  }

  return items;
}

function buildValueProofs({ apps, users, locations, governance, policyActions, activityModes, promptIntelligence }) {
  if (!apps.length) {
    return [
      "No AI applications were detected in the selected timeframe, so the strongest value story here is baseline validation rather than exposure reduction.",
      "If the customer expects usage, widen the timeframe or review the discovery-hint list before presenting a conclusion.",
      "This assessment still proves the team can validate AI activity quickly with read-only access and no tenant-side deployment work.",
    ];
  }

  const proofs = [];
  proofs.push(
    `${apps.length} AI apps were observed across ${users.length} ranked users${locations.length ? ` and ${locations.length} visible locations` : ""}, proving the assessment can map AI exposure quickly.`,
  );

  if (governance.review.count) {
    proofs.push(
      `${governance.review.count} visible AI apps were outside the approved or explicitly sanctioned set, representing ${formatPercent(governance.review.share)} of measured AI traffic.`,
    );
  } else {
    proofs.push(
      `${governance.governedCount} visible AI apps were either approved or explicitly sanctioned, giving the customer a clear governance baseline.`,
    );
  }

  if (policyActions.total) {
    proofs.push(
      `Cato returned ${formatNumber(policyActions.total)} AI security actions, including ${formatNumber(policyActions.blocked)} blocked outcomes, proving this is already a control conversation and not just a visibility conversation.`,
    );
  } else if (activityModes.dominant) {
    proofs.push(
      `The assessment separated web assistants, coding tools, and AI platforms or APIs, which helps the CISO target policy by usage pattern instead of treating all AI use as one bucket.`,
    );
  } else if (!promptIntelligence.hasSemanticDetail) {
    proofs.push(
      "Even without prompt topic or intent detail, the tenant still exposes enough application, user, and security-event data to support an executive governance discussion.",
    );
  }

  return proofs.slice(0, 3);
}

function buildHeadline({ apps, users, activityModes, shadowApps, shadowShare, detectionCount, governance, policyActions }) {
  if (!apps.length) {
    return {
      title: "No AI activity matched the current detection list",
      body: "The selected timeframe did not return recognizable AI application usage, or the tracked-app list needs to be widened for this customer environment.",
    };
  }

  if (policyActions.blocked >= 1000 || policyActions.total >= 5000) {
    return {
      title: "AI activity is already driving security actions",
      body: `Cato returned ${formatNumber(policyActions.total)} AI security actions in this timeframe, including ${formatNumber(policyActions.blocked)} blocked outcomes, which gives the CISO concrete evidence that AI governance is already operationally relevant.`,
    };
  }

  if (governance.review.count >= 5 && governance.review.share >= 0.25) {
    return {
      title: "Unmanaged AI use is already material",
      body: `A meaningful share of the observed AI footprint sits outside the approved or explicitly sanctioned set, which gives the CISO a strong governance and visibility story to react to.`,
    };
  }

  const proxyMode = activityModes.items.find((item) => item.mode === "proxy");
  const agenticMode = activityModes.items.find((item) => item.mode === "agentic");
  if ((proxyMode?.share || 0) >= 0.18 || (agenticMode?.share || 0) >= 0.12) {
    return {
      title: "AI usage goes beyond simple web chat tools",
      body: "The report shows people using AI through coding tools, desktop agents, or managed AI platforms and APIs, which makes the visibility story operational rather than theoretical.",
    };
  }

  if (users.length >= 10 || detectionCount > 0) {
    return {
      title: "AI usage is broad enough to be executive-relevant",
      body: "The account shows enough spread across users, applications, or detections to support a leadership-level conversation about visibility, governance, and policy posture.",
    };
  }

  return {
    title: "AI usage is present, but still somewhat concentrated",
    body: "The report shows identifiable AI activity and can be used to frame how quickly that usage could become a governance problem if it expands.",
  };
}

function buildNarrativeText({ config, totals, apps, users, locations, shadowApps, shadowShare, detections, governance, policyActions, planEditions, activityModes, promptIntelligence, snapshotText, warnings }) {
  if (!apps.length) {
    return [
      `${config.accountLabel} did not return recognizable AI application activity for ${formatDateRange(config.startDate, config.endDate)} using the current detection list.`,
      "This usually means either the customer has very limited AI usage in the selected range or the tracked application list needs to be expanded before customer-facing conclusions are drawn.",
    ];
  }

  const topApp = apps[0];
  const topUserCount = users.length;
  const browserMode = activityModes.items.find((item) => item.mode === "browser");
  const agenticMode = activityModes.items.find((item) => item.mode === "agentic");
  const proxyMode = activityModes.items.find((item) => item.mode === "proxy");
  const governanceLine = governance.review.count
    ? `${governance.review.count} visible AI app${governance.review.count === 1 ? "" : "s"} sat outside the approved or explicitly sanctioned set, representing ${formatPercent(governance.review.share)} of measured AI traffic. ${governance.sanctioned.count ? `${governance.sanctioned.count} app${governance.sanctioned.count === 1 ? "" : "s"} were explicitly sanctioned and ${governance.approved.count} matched the approved list.` : `${governance.approved.count} app${governance.approved.count === 1 ? "" : "s"} matched the approved list.`}`
    : `${governance.governedCount} visible AI app${governance.governedCount === 1 ? "" : "s"} were either approved or explicitly sanctioned in the current view.`;
  const detectionLine = !config.includeDetectionSignals
    ? "The optional prompt and policy queries were not enabled for this run, so the report should lean on visibility, access patterns, and shadow AI instead."
    : policyActions.total
    ? `The optional detections query returned ${formatNumber(policyActions.total)} AI security action${policyActions.total === 1 ? "" : "s"}, including ${formatNumber(policyActions.blocked)} blocked and ${formatNumber(policyActions.allowed)} allowed outcomes, which shows the solution is not only observing AI activity but also surfacing enforcement evidence.`
    : detections.length
    ? `The optional detections query also returned ${formatNumber(detections.reduce((sum, item) => sum + item.count, 0))} policy or data-protection signal${detections.length === 1 ? "" : "s"}, which strengthens the prompt-governance story.`
    : "Prompt-level or policy-level detections were not returned in the current API view, so the conversation should lean on usage visibility and shadow AI instead.";
  const modeLine = `${activityModeMeta.browser.label} represented ${formatPercent(browserMode?.share || 0)} of measured AI traffic, while ${activityModeMeta.agentic.label.toLowerCase()} represented ${formatPercent(agenticMode?.share || 0)} and ${activityModeMeta.proxy.label.toLowerCase()} represented ${formatPercent(proxyMode?.share || 0)}.`;
  const locationLine = locations.length
    ? `The highest-ranked access location in the assessment was ${describeLocationForNarrative(config, locations[0])}, which helps connect the usage story to a concrete geography or office footprint.`
    : "Location-level visibility was limited in the current data pull, so the report leans more heavily on sites and user spread.";
  const editionLine = planEditions.length
    ? `The visible AI footprint includes ${planEditions.slice(0, 3).map((item) => `${item.edition.toLowerCase()} variants at ${formatPercent(item.share)}`).join(", ")}, which helps separate free, paid, enterprise, and API-style access patterns.`
    : "";
  const promptLine = !config.includeDetectionSignals
    ? "Prompt intelligence was not populated for this run because the optional prompt query was disabled."
    : promptIntelligence.hasSemanticDetail
    ? `Prompt intelligence is available beyond signals alone: the API exposed enough detail to derive ${formatNumber(promptIntelligence.topics.length)} topic${promptIntelligence.topics.length === 1 ? "" : "s"} and ${formatNumber(promptIntelligence.intents.length)} intent${promptIntelligence.intents.length === 1 ? "" : "s"} for internal analysis.`
    : policyActions.total
      ? "The public API did not return topic or intent metadata for this timeframe, but it did return action-level AI security evidence that still supports a strong governance and value story."
    : promptIntelligence.themes.length
      ? `Prompt intelligence is partially visible across the selected assistant apps: the account exposed theme, topic, or intent-level metadata such as ${promptIntelligence.themes.slice(0, 2).map((item) => item.label).join(" and ")}, even though raw prompt text was not exposed.`
      : "Prompt intelligence is currently limited to generic prompt or policy detections rather than actual prompt topic or intent content for the selected assistant apps, so the value story should stay focused on governance visibility and policy evidence.";
  const warningLine = warnings.length ? `Data caveats: ${warnings.join(" ")}` : "";

  return [
    `${config.accountLabel} showed ${apps.length} tracked AI application${apps.length === 1 ? "" : "s"} between ${formatDateRange(config.startDate, config.endDate)}. The largest visible footprint was ${topApp.name}, which accounted for ${formatBytes(topApp.traffic)} of AI traffic and ${formatNumber(topApp.flows)} interaction flows.`,
    `The activity reached ${formatNumber(topUserCount)} ranked user${topUserCount === 1 ? "" : "s"} in the report, with an aggregate AI footprint of ${formatBytes(totals.traffic)} across ${formatNumber(totals.flows)} measured flows. ${snapshotText !== "Snapshot unavailable" ? `At capture time, the environment snapshot showed ${snapshotText.toLowerCase()}.` : ""}`,
    `${modeLine} ${locationLine} ${editionLine}`.trim(),
    `${governanceLine} ${detectionLine} ${promptLine}`,
    config.executiveContext ? `Executive framing: ${config.executiveContext}` : "",
    warningLine,
  ].filter(Boolean);
}

function scaleRatio(value, ceiling) {
  if (!Number.isFinite(Number(value)) || !Number.isFinite(Number(ceiling)) || Number(ceiling) <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(1, Number(value) / Number(ceiling)));
}

function scaleLogRatio(value, ceiling) {
  const numericValue = Number(value);
  const numericCeiling = Number(ceiling);
  if (!Number.isFinite(numericValue) || !Number.isFinite(numericCeiling) || numericValue <= 0 || numericCeiling <= 1) {
    return 0;
  }
  return Math.max(0, Math.min(1, Math.log10(numericValue + 1) / Math.log10(numericCeiling + 1)));
}

function setCardVisual(node, fill, tone = "brand") {
  const card = node?.closest(".stat-card");
  if (!card) {
    return;
  }

  const palette = {
    brand: {
      start: "#138c65",
      end: "#2cc18f",
      orb: "rgba(19, 140, 101, 0.18)",
      edge: "rgba(19, 140, 101, 0.16)",
    },
    sand: {
      start: "#d18f33",
      end: "#f3b46f",
      orb: "rgba(243, 180, 111, 0.22)",
      edge: "rgba(243, 180, 111, 0.16)",
    },
    danger: {
      start: "#b64a33",
      end: "#db7b64",
      orb: "rgba(192, 77, 52, 0.18)",
      edge: "rgba(192, 77, 52, 0.14)",
    },
    neutral: {
      start: "#6c8b80",
      end: "#a8bab3",
      orb: "rgba(108, 139, 128, 0.16)",
      edge: "rgba(108, 139, 128, 0.12)",
    },
  }[tone] || {
    start: "#138c65",
    end: "#2cc18f",
    orb: "rgba(19, 140, 101, 0.18)",
    edge: "rgba(19, 140, 101, 0.16)",
  };

  const clamped = Math.max(0, Math.min(1, Number(fill) || 0));
  card.style.setProperty("--meter-fill", `${clamped > 0 ? Math.max(clamped * 100, 10) : 0}%`);
  card.style.setProperty("--meter-start", palette.start);
  card.style.setProperty("--meter-end", palette.end);
  card.style.setProperty("--orb-color", palette.orb);
  card.style.setProperty("--card-edge", palette.edge);
}

function resetDashboardCardVisuals() {
  [
    el.aiAppsValue,
    el.aiUsersValue,
    el.aiFlowsValue,
    el.aiTrafficValue,
    el.shadowValue,
    el.promptToolsValue,
    el.agenticValue,
    el.proxyValue,
  ].forEach((node) => setCardVisual(node, 0, "neutral"));
}

function paintDashboardCardVisuals(report) {
  const agenticShare = report.activityModes.items.find((item) => item.mode === "agentic")?.share || 0;
  const proxyShare = report.activityModes.items.find((item) => item.mode === "proxy")?.share || 0;

  setCardVisual(el.aiAppsValue, scaleRatio(report.apps.length, 18), "brand");
  setCardVisual(el.aiUsersValue, scaleRatio(report.users.length, 40), "neutral");
  setCardVisual(el.aiFlowsValue, scaleLogRatio(report.totals.flows, 100000), "brand");
  setCardVisual(el.aiTrafficValue, scaleLogRatio(report.totals.traffic, 100 * 1024 ** 3), "sand");
  setCardVisual(el.shadowValue, report.shadowShare, report.shadowShare >= 0.2 ? "danger" : "sand");
  setCardVisual(el.promptToolsValue, scaleLogRatio(report.policyActions.total, 100000), report.policyActions.blocked ? "danger" : "sand");
  setCardVisual(el.agenticValue, agenticShare, agenticShare >= 0.12 ? "danger" : "neutral");
  setCardVisual(el.proxyValue, proxyShare, proxyShare >= 0.18 ? "sand" : "neutral");
}

function renderReport(report) {
  updateStaticChips();
  el.captureChip.textContent = `Captured ${new Date().toLocaleString()}`;
  el.pressureValue.textContent = report.pressureIndex;
  el.pressureGauge.style.background =
    `radial-gradient(circle closest-side, white 66%, transparent 67%), conic-gradient(${toneColor(report.pressureIndex)} ${report.pressureIndex * 3.6}deg, rgba(19, 140, 101, 0.14) 0deg)`;
  el.pressureLabel.textContent = pressureLabel(report.pressureIndex);

  el.headlineTitle.textContent = report.headline.title;
  el.headlineBody.textContent = report.headline.body;
  el.timeframeValue.textContent = formatDateRange(report.config.startDate, report.config.endDate);
  el.topSignalValue.textContent = report.topApp ? report.topApp.name : "No AI activity";
  el.shadowSignalValue.textContent = report.shadowApps.length
    ? `${report.shadowApps.length} unapproved app${report.shadowApps.length === 1 ? "" : "s"}`
    : "No shadow AI found";
  el.executiveSummary.textContent = report.reportText[0];

  el.insightList.innerHTML = report.insights.map((item) => `<div class="insight-item">${escapeHtml(item)}</div>`).join("");
  el.valueProofList.innerHTML = report.valueProofs.map((item) => `<div class="insight-item">${escapeHtml(item)}</div>`).join("");

  el.aiAppsValue.textContent = formatNumber(report.apps.length);
  el.aiAppsDetail.textContent = report.meaningfulEditions.length
    ? report.meaningfulEditions.slice(0, 3).map((item) => `${item.edition}: ${formatNumber(item.apps)}`).join(" · ")
    : "Edition split was not exposed clearly in application names for this timeframe.";
  el.aiUsersValue.textContent = formatNumber(report.users.length);
  el.aiUsersDetail.textContent = report.config.anonymizeNames
    ? "Names are currently masked for customer-safe output."
    : "Names are currently shown in the report.";
  el.aiFlowsValue.textContent = formatNumber(report.totals.flows);
  el.aiFlowsDetail.textContent = "Approximation based on application flows created.";
  el.aiTrafficValue.textContent = formatBytes(report.totals.traffic);
  el.aiTrafficDetail.textContent = `Top app: ${report.topApp ? report.topApp.name : "N/A"}.`;
  el.shadowValue.textContent = formatPercent(report.shadowShare);
  el.shadowDetail.textContent = report.governance.review.count
    ? `${report.governance.review.count} app${report.governance.review.count === 1 ? "" : "s"} need governance review and represent ${formatPercent(report.governance.review.share)} of measured AI traffic.`
    : "No unmanaged AI was found from the current approved and sanctioned view.";
  el.promptToolsValue.textContent = report.config.includeDetectionSignals ? formatNumber(report.policyActions.total) : "Not run";
  el.promptToolsDetail.textContent = !report.config.includeDetectionSignals
    ? "Enable the optional detections query to show AI security actions."
    : report.policyActions.total
      ? `${formatNumber(report.policyActions.blocked)} blocked · ${formatNumber(report.policyActions.allowed)} allowed`
      : "No AI security actions were returned in this timeframe.";
  el.agenticValue.textContent = formatPercent(report.activityModes.items.find((item) => item.mode === "agentic")?.share || 0);
  el.agenticDetail.textContent = report.activityModes.items.find((item) => item.mode === "agentic")?.topApp
    ? `Top coding tool or desktop agent: ${report.activityModes.items.find((item) => item.mode === "agentic").topApp.name}.`
    : "No AI coding tool or desktop agent was identified in the current footprint.";
  el.proxyValue.textContent = formatPercent(report.activityModes.items.find((item) => item.mode === "proxy")?.share || 0);
  el.proxyDetail.textContent = report.activityModes.items.find((item) => item.mode === "proxy")?.topApp
    ? `Top AI platform or API path: ${report.activityModes.items.find((item) => item.mode === "proxy").topApp.name}.`
    : "No managed AI platform or API path was identified.";

  if (report.config.includeDetectionSignals) {
    paintBadge(el.promptBadge, report.promptIntelligence.visibility, report.promptIntelligence.tone);
    el.promptVisibilityValue.textContent = report.promptIntelligence.hasSemanticDetail
      ? "Topic / intent returned"
      : report.policyActions.total
        ? "Actions only"
        : "Not returned";
    el.promptSignalValue.textContent = report.promptIntelligence.hasSemanticDetail
      ? report.promptIntelligence.dominantSignal
      : report.policyActions.dominantAction
        ? `${report.policyActions.dominantAction.label} (${formatNumber(report.policyActions.dominantAction.count)})`
        : "Awaiting data";
    el.promptThemeCountValue.textContent = formatNumber(report.promptIntelligence.topics.length || report.promptIntelligence.themes.length);
    el.promptIntentCountValue.textContent = formatNumber(report.promptIntelligence.intents.length);
    el.promptSummary.textContent = report.promptIntelligence.hasSemanticDetail
      ? report.promptIntelligence.summary
      : report.policyActions.total
        ? `This public API path did not return topic or intent metadata for the selected timeframe, but it did return ${formatNumber(report.policyActions.total)} AI security actions, including ${formatNumber(report.policyActions.blocked)} blocked and ${formatNumber(report.policyActions.allowed)} allowed decisions.`
        : report.promptIntelligence.summary;
  } else {
    paintBadge(el.promptBadge, "Optional query disabled", "neutral");
    el.promptVisibilityValue.textContent = "Query not run";
    el.promptSignalValue.textContent = "Awaiting data";
    el.promptThemeCountValue.textContent = "0";
    el.promptIntentCountValue.textContent = "0";
    el.promptSummary.textContent = "Enable the optional detections query to show AI security actions and any topic or intent metadata this account exposes.";
  }

  el.topAppValue.textContent = report.topApp ? report.topApp.name : "No AI activity";
  el.topUserValue.textContent = report.topUser ? displayName(report, "user", report.topUser.label) : "No ranked user";
  el.topLocationValue.textContent = report.topLocation ? displayLocationLabel(report, report.topLocation) : "No ranked location";
  el.policyValue.textContent = report.policyActions.total ? formatNumber(report.policyActions.total) : "No actions";
  el.exposureNarrative.textContent = report.valueProofs[2] || report.valueProofs[1] || report.headline.body;

  paintBadge(el.appsSubtitle, report.apps.length ? `${report.apps.length} apps ranked` : "No apps", report.apps.length ? "good" : "neutral");
  paintBadge(
    el.shadowBadge,
    report.shadowApps.length ? `${report.shadowApps.length} shadow apps` : "No shadow AI",
    report.shadowApps.length ? (report.shadowShare > 0.2 ? "risk" : "warn") : "good",
  );
  paintBadge(el.userBadge, report.users.length ? `${report.users.length} users ranked` : "No user data", report.users.length ? "good" : "neutral");
  paintBadge(
    el.locationBadge,
    `${report.locations.length} locations / ${report.users.length} users`,
    report.locations.length || report.users.length ? "good" : "neutral",
  );
  paintBadge(
    el.modeBadge,
    report.activityModes.items.filter((item) => item.share > 0).length
      ? `${report.activityModes.items.filter((item) => item.share > 0).length} access path${report.activityModes.items.filter((item) => item.share > 0).length === 1 ? "" : "s"} visible`
      : "No access split",
    report.activityModes.items.some((item) => item.share > 0) ? "good" : "neutral",
  );
  paintBadge(
    el.detectionsBadge,
    report.config.includeDetectionSignals
      ? report.detections.length
        ? `${report.detections.length} patterns returned`
        : "No detections returned"
      : "Optional query disabled",
    report.config.includeDetectionSignals && report.detections.length ? "warn" : "neutral",
  );
  paintBadge(
    el.signalBoardBadge,
    report.activityModes.dominant ? `${report.activityModes.dominant.label} leads` : "Awaiting data",
    report.activityModes.dominant ? "good" : "neutral",
  );

  renderActivityChart(report.chart);
  renderSignalBoard(report);
  renderActivityModes(report);
  renderApplications(report);
  renderShadowApps(report);
  renderUsers(report);
  renderLocations(report);
  renderUsersCompact(report);
  renderDevices(report);
  renderPromptIntelligence(report);
  renderDetections(report);
  renderNarrative(report);
  paintDashboardCardVisuals(report);
}

function renderDefaultState() {
  updateStaticChips();
  el.captureChip.textContent = "No data captured yet";
  el.pressureValue.textContent = "0";
  el.pressureGauge.style.background =
    "radial-gradient(circle closest-side, white 66%, transparent 67%), conic-gradient(rgba(19, 140, 101, 0.14) 0deg, rgba(19, 140, 101, 0.14) 360deg)";
  el.pressureLabel.textContent = "Load an assessment to calculate the current exposure signal.";
  el.headlineTitle.textContent = "No assessment loaded";
  el.headlineBody.textContent =
    "This report is designed to spotlight AI activity, unmanaged usage, user and location spread, and action-level security evidence in a format that is easy to walk through with a customer leadership team.";
  el.timeframeValue.textContent = "Custom range";
  el.topSignalValue.textContent = "Awaiting data";
  el.shadowSignalValue.textContent = "Awaiting data";
  el.executiveSummary.textContent = "Pull a dataset to populate the CISO-ready summary and recommendations.";
  el.insightList.innerHTML = "";
  el.valueProofList.innerHTML = "";
  el.aiAppsValue.textContent = "0";
  el.aiUsersValue.textContent = "0";
  el.aiFlowsValue.textContent = "0";
  el.aiTrafficValue.textContent = "0 B";
  el.shadowValue.textContent = "0%";
  el.promptToolsValue.textContent = "0";
  el.agenticValue.textContent = "0%";
  el.proxyValue.textContent = "0%";
  el.aiAppsDetail.textContent = "All detected AI app variants, including free, paid, enterprise, and API editions.";
  el.aiUsersDetail.textContent = "Distinct users associated with AI application activity.";
  el.aiFlowsDetail.textContent = "Approximation based on application flows created.";
  el.aiTrafficDetail.textContent = "Combined upstream and downstream traffic for detected AI apps.";
  el.shadowDetail.textContent = "Traffic share attributed to AI apps outside the approved list.";
  el.promptToolsDetail.textContent = "Policy actions returned by Cato AI security events.";
  el.agenticDetail.textContent = "Share of AI traffic linked to coding tools and desktop agents such as Claude Code or Cursor.";
  el.proxyDetail.textContent = "Share of AI traffic linked to managed AI platforms or APIs such as OpenAI API, Bedrock, or Vertex AI.";
  el.promptVisibilityValue.textContent = "Unknown";
  el.promptSignalValue.textContent = "Awaiting data";
  el.promptThemeCountValue.textContent = "0";
  el.promptIntentCountValue.textContent = "0";
  el.promptSummary.textContent =
    "Load a dataset to show whether this account returned topic or intent metadata, action-level AI security evidence, or both.";
  el.browserModeValue.textContent = "0%";
  el.agenticModeValue.textContent = "0%";
  el.proxyModeValue.textContent = "0%";
  el.modeDetectionValue.textContent = "0";
  el.activityModeNarrative.textContent =
    "Load a report to break the AI footprint into three simple buckets: web assistants, coding tools, and AI platforms or APIs.";
  el.topAppValue.textContent = "None yet";
  el.topUserValue.textContent = "None yet";
  el.topLocationValue.textContent = "None yet";
  el.policyValue.textContent = "Not queried";
  el.exposureNarrative.textContent =
    "This panel translates the raw query results into an executive value story for the customer review.";
  paintBadge(el.modeBadge, "Awaiting data", "neutral");
  paintBadge(el.promptBadge, "Awaiting data", "neutral");
  paintBadge(el.appsSubtitle, "No data", "neutral");
  paintBadge(el.shadowBadge, "Awaiting data", "neutral");
  paintBadge(el.userBadge, "Awaiting data", "neutral");
  paintBadge(el.locationBadge, "Awaiting data", "neutral");
  paintBadge(el.detectionsBadge, "Optional query", "neutral");
  el.activityModeTable.innerHTML = `<div class="empty-state">No access-pattern data loaded yet.</div>`;
  el.topAppsTable.innerHTML = `<div class="empty-state">No application data loaded yet.</div>`;
  el.shadowAppsTable.innerHTML = `<div class="empty-state">No shadow AI findings yet.</div>`;
  el.topUsersTable.innerHTML = `<div class="empty-state">No user data loaded yet.</div>`;
  el.topLocationsTable.innerHTML = `<div class="empty-state">No location data loaded yet.</div>`;
  el.topUsersCompactTable.innerHTML = `<div class="empty-state">No user data loaded yet.</div>`;
  el.topDevicesTable.innerHTML = `<div class="empty-state">No device data loaded yet.</div>`;
  el.promptTopicsTable.innerHTML = `<div class="empty-state">Prompt topics will appear here when the account exposes enough metadata to summarize them.</div>`;
  el.promptIntentsTable.innerHTML = `<div class="empty-state">Prompt intents will appear here when the account exposes enough metadata to summarize them.</div>`;
  el.detectionsTable.innerHTML = `<div class="empty-state">Security actions appear here when the account exposes AI or data-protection events through the API.</div>`;
  el.reportNarrative.innerHTML = "Load a dataset to generate the customer-facing summary and recommended discussion points.";
  paintBadge(el.signalBoardBadge, "Awaiting data", "neutral");
  el.modeDonut.style.background =
    "radial-gradient(circle closest-side, rgba(255,255,255,0.98) 61%, transparent 62%), conic-gradient(rgba(19, 140, 101, 0.16) 360deg, rgba(16, 44, 38, 0.08) 0deg)";
  el.modeDonutValue.textContent = "0%";
  el.modeDonutCaption.textContent = "Load a report to highlight the strongest AI access path.";
  el.editionStack.innerHTML = `<div class="signal-stack__empty">No edition mix data yet.</div>`;
  el.editionLegend.innerHTML = "";
  el.promptTopicChips.innerHTML = `<span class="signal-chip signal-chip--muted">No prompt topics yet</span>`;
  el.promptIntentChips.innerHTML = `<span class="signal-chip signal-chip--muted">No prompt intents yet</span>`;
  resetDashboardCardVisuals();
  renderActivityChart([]);
}

function renderSignalBoard(report) {
  const dominantMode = report.activityModes.dominant;
  const share = dominantMode?.share || 0;
  const tone = dominantMode?.mode === "proxy" ? "var(--sand)" : dominantMode?.mode === "agentic" ? "var(--danger)" : "var(--brand)";
  el.modeDonut.style.background =
    `radial-gradient(circle closest-side, rgba(255,255,255,0.98) 61%, transparent 62%), conic-gradient(${tone} ${Math.max(share * 360, 10)}deg, rgba(16, 44, 38, 0.08) 0deg)`;
  el.modeDonutValue.textContent = formatPercent(share);
  el.modeDonutCaption.textContent = dominantMode
    ? `${dominantMode.label} is the strongest visible AI path, led by ${dominantMode.topApp?.name || "the current top app"}.`
    : "Load a report to highlight the strongest AI access path.";

  if (!report.planEditions.length) {
    el.editionStack.innerHTML = `<div class="signal-stack__empty">No edition mix data yet.</div>`;
    el.editionLegend.innerHTML = "";
  } else {
    const total = report.planEditions.reduce((sum, item) => sum + item.share, 0) || 1;
    el.editionStack.innerHTML = report.planEditions
      .slice(0, 4)
      .map((item) => {
        const width = Math.max((item.share / total) * 100, 8);
        return `<span class="signal-stack__segment" style="width:${width}%; background:${editionColor(item.edition)}"></span>`;
      })
      .join("");
    el.editionLegend.innerHTML = report.planEditions
      .slice(0, 4)
      .map(
        (item) => `
          <div class="signal-legend__item">
            <i style="background:${editionColor(item.edition)}"></i>
            <span>${escapeHtml(item.edition)} ${formatPercent(item.share)}</span>
          </div>
        `,
      )
      .join("");
  }

  el.promptTopicChips.innerHTML = report.promptIntelligence.topics.length
    ? report.promptIntelligence.topics
        .slice(0, 5)
        .map((item) => `<span class="signal-chip">${escapeHtml(item.label)} <strong>${formatNumber(item.count)}</strong></span>`)
        .join("")
    : report.promptIntelligence.themes.length
      ? report.promptIntelligence.themes
          .slice(0, 5)
          .map((item) => `<span class="signal-chip">${escapeHtml(item.label)} <strong>${formatNumber(item.count)}</strong></span>`)
          .join("")
    : `<span class="signal-chip signal-chip--muted">No prompt topics surfaced</span>`;

  el.promptIntentChips.innerHTML = report.promptIntelligence.intents.length
    ? report.promptIntelligence.intents
        .slice(0, 5)
        .map((item) => `<span class="signal-chip signal-chip--muted">${escapeHtml(item.label)} <strong>${formatNumber(item.count)}</strong></span>`)
        .join("")
    : `<span class="signal-chip signal-chip--muted">No prompt intents surfaced</span>`;
}

function renderActivityModes(report) {
  const items = report.activityModes.items;
  const browser = items.find((item) => item.mode === "browser");
  const agentic = items.find((item) => item.mode === "agentic");
  const proxy = items.find((item) => item.mode === "proxy");

  el.browserModeValue.textContent = formatPercent(browser?.share || 0);
  el.agenticModeValue.textContent = formatPercent(agentic?.share || 0);
  el.proxyModeValue.textContent = formatPercent(proxy?.share || 0);
  el.modeDetectionValue.textContent = report.config.includeDetectionSignals ? formatNumber(report.detectionCount) : "0";
  el.activityModeNarrative.textContent = report.config.includeDetectionSignals
    ? report.activityModes.summary
    : report.activityModes.dominant
      ? `${report.activityModes.dominant.label} currently account for the largest visible share of AI traffic at ${formatPercent(report.activityModes.dominant.share)}. The optional security-signal query was not enabled for this run.`
      : report.activityModes.summary;

  if (!items.some((item) => item.traffic > 0 || item.flows > 0)) {
    el.activityModeTable.innerHTML = `<div class="empty-state">No web-assistant, coding-tool, or AI-platform traffic was classified from the detected AI apps.</div>`;
    return;
  }

  const rows = items.map((item) => `
    <tr>
      <td class="row-label">${escapeHtml(item.label)}</td>
      <td>${formatPercent(item.share)}</td>
      <td>${formatNumber(item.flows)}</td>
      <td>${escapeHtml(item.topApp?.name || activityModeMeta[item.mode].empty)}</td>
    </tr>
  `);

  el.activityModeTable.innerHTML = tableMarkup(["Access pattern", "Traffic share", "Interactions", "Most visible example"], rows.join(""));
}

function renderApplications(report) {
  if (!report.apps.length) {
    el.topAppsTable.innerHTML = `<div class="empty-state">No tracked AI applications matched the current timeframe.</div>`;
    return;
  }

  const maxTraffic = report.apps[0].traffic || 1;
  const rows = report.apps.slice(0, 12).map((app) => {
    const percent = Math.round((app.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td>
          <div class="row-label">${escapeHtml(app.name)}</div>
          <div class="cell-subnote">${escapeHtml(applicationSubnote(app))}</div>
        </td>
        <td>${riskPill(app.riskLevel)}</td>
        <td class="bar-cell">
          ${barMarkup(percent, formatBytes(app.traffic))}
        </td>
        <td>${formatNumber(app.flows)}</td>
        <td>${statusPill(app.approved ? "Approved" : app.sanctioned === true ? "Sanctioned" : "Review")}</td>
      </tr>
    `;
  });

  el.topAppsTable.innerHTML = tableMarkup(
    ["Application", "Cato risk", "Traffic share", "Interactions", "Governance"],
    rows.join(""),
  );
}

function renderShadowApps(report) {
  if (!report.shadowApps.length) {
    el.shadowAppsTable.innerHTML = `<div class="empty-state">No shadow AI was identified from the current approved-app list.</div>`;
    return;
  }

  const maxTraffic = report.shadowApps[0].traffic || 1;
  const rows = report.shadowApps.slice(0, 10).map((app) => {
    const percent = Math.round((app.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td>
          <div class="row-label">${escapeHtml(app.name)}</div>
          <div class="cell-subnote">${escapeHtml(applicationSubnote(app))}</div>
        </td>
        <td>${riskPill(app.riskLevel)}</td>
        <td class="bar-cell">${barMarkup(percent, formatBytes(app.traffic), "sand")}</td>
        <td>${formatNumber(app.flows)}</td>
      </tr>
    `;
  });

  el.shadowAppsTable.innerHTML = tableMarkup(["Application", "Cato risk", "Traffic share", "Interactions"], rows.join(""));
}

function renderUsers(report) {
  if (!report.users.length) {
    el.topUsersTable.innerHTML = `<div class="empty-state">No user-ranking data was returned by the current app analytics query.</div>`;
    return;
  }

  const maxTraffic = report.users[0].traffic || 1;
  const rows = report.users.slice(0, 10).map((user) => {
    const percent = Math.round((user.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td class="row-label">${escapeHtml(displayName(report, "user", user.label))}</td>
        <td class="bar-cell">${barMarkup(percent, formatBytes(user.traffic))}</td>
        <td>${formatNumber(user.flows)}</td>
        <td>${user.appCount ? formatNumber(user.appCount) : "n/a"}</td>
      </tr>
    `;
  });

  el.topUsersTable.innerHTML = tableMarkup(["User", "Traffic share", "Flows", "Apps"], rows.join(""));
}

function renderLocations(report) {
  if (!report.locations.length) {
    el.topLocationsTable.innerHTML = `<div class="empty-state">No location-ranking data was returned.</div>`;
    return;
  }

  const maxTraffic = report.locations[0].traffic || 1;
  const rows = report.locations.slice(0, 8).map((location) => {
    const percent = Math.round((location.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td class="row-label">${escapeHtml(displayLocationLabel(report, location))}</td>
        <td class="bar-cell">${barMarkup(percent, formatBytes(location.traffic), "sand")}</td>
        <td>${formatNumber(location.flows)}</td>
      </tr>
    `;
  });

  el.topLocationsTable.innerHTML = tableMarkup(["Location", "Traffic share", "Flows"], rows.join(""));
}

function renderUsersCompact(report) {
  if (!report.users.length) {
    el.topUsersCompactTable.innerHTML = `<div class="empty-state">No user-ranking data was returned.</div>`;
    return;
  }

  const maxTraffic = report.users[0].traffic || 1;
  const rows = report.users.slice(0, 6).map((user) => {
    const percent = Math.round((user.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td class="row-label">${escapeHtml(displayName(report, "user", user.label))}</td>
        <td class="bar-cell">${barMarkup(percent, formatBytes(user.traffic), "sand")}</td>
        <td>${formatNumber(user.flows)}</td>
      </tr>
    `;
  });

  el.topUsersCompactTable.innerHTML = tableMarkup(["User", "Traffic share", "Flows"], rows.join(""));
}

function renderDevices(report) {
  if (!report.devices.length) {
    el.topDevicesTable.innerHTML = `<div class="empty-state">No device-ranking data was returned.</div>`;
    return;
  }

  const maxTraffic = report.devices[0].traffic || 1;
  const rows = report.devices.slice(0, 8).map((device) => {
    const percent = Math.round((device.traffic / maxTraffic) * 100);
    return `
      <tr>
        <td class="row-label">${escapeHtml(displayName(report, "device", device.label))}</td>
        <td class="bar-cell">${barMarkup(percent, formatBytes(device.traffic))}</td>
        <td>${formatNumber(device.flows)}</td>
      </tr>
    `;
  });

  el.topDevicesTable.innerHTML = tableMarkup(["Device", "Traffic share", "Flows"], rows.join(""));
}

function renderPromptIntelligence(report) {
  const prompt = report.promptIntelligence;
  const topicRowsSource = prompt.topics.length ? prompt.topics : prompt.themes;

  if (!report.config.includeDetectionSignals) {
    el.promptTopicsTable.innerHTML = `<div class="empty-state">Enable the optional detections query if you want to test whether this account exposes topic metadata through the public API.</div>`;
    el.promptIntentsTable.innerHTML = `<div class="empty-state">Intent highlights only appear when the public events path returns that metadata for this account and timeframe.</div>`;
    return;
  }

  if (!topicRowsSource.length) {
    el.promptTopicsTable.innerHTML = `<div class="empty-state">The public API did not return topic metadata for the selected timeframe. This does not remove the value story, because action-level AI security evidence can still be reported.</div>`;
  } else {
    const rows = topicRowsSource.map((item) => `
      <tr>
        <td class="row-label">${escapeHtml(item.label)}</td>
        <td>${escapeHtml(item.app)}</td>
        <td>${formatNumber(item.count)}</td>
      </tr>
    `);
    el.promptTopicsTable.innerHTML = tableMarkup(["Topic", "App scope", "Signals"], rows.join(""));
  }

  if (!prompt.intents.length) {
    el.promptIntentsTable.innerHTML = `<div class="empty-state">The public API did not return intent metadata for the selected timeframe.</div>`;
    return;
  }

  const intentRows = prompt.intents.map((item) => `
    <tr>
      <td class="row-label">${escapeHtml(item.label)}</td>
      <td>${escapeHtml(item.app)}</td>
      <td>${formatNumber(item.count)}</td>
    </tr>
  `);
  el.promptIntentsTable.innerHTML = tableMarkup(["Intent", "App scope", "Signals"], intentRows.join(""));
}

function renderDetections(report) {
  if (!report.config || !report.config.includeDetectionSignals) {
    el.detectionsTable.innerHTML = `<div class="empty-state">Enable the optional detections query if you want to surface AI security actions and policy evidence.</div>`;
    return;
  }

  if (!report.detections.length) {
    el.detectionsTable.innerHTML = `<div class="empty-state">No AI-related security actions or data-protection events were returned for this timeframe.</div>`;
    return;
  }

  const rows = report.detections.slice(0, 10).map((item) => `
    <tr>
      <td class="row-label">${escapeHtml(item.action)}</td>
      <td>${escapeHtml(item.subtype)}</td>
      <td>${formatNumber(item.count)}</td>
    </tr>
  `);

  el.detectionsTable.innerHTML = tableMarkup(["Action", "Policy source", "Count"], rows.join(""));
}

function renderNarrative(report) {
  el.reportNarrative.innerHTML = report.reportText.map((paragraph) => `<p>${escapeHtml(paragraph)}</p>`).join("");
}

function renderActivityChart(points) {
  if (!points.length) {
    el.activityChart.innerHTML = `
      <text x="50%" y="50%" text-anchor="middle" class="chart-label">
        Load a report to render the AI activity trend.
      </text>
    `;
    el.activityChartMeta.textContent = "No timeseries data loaded yet.";
    return;
  }

  const width = 720;
  const height = 280;
  const padding = { top: 22, right: 22, bottom: 28, left: 32 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const flowMax = Math.max(...points.map((point) => point.flows), 1);
  const trafficMax = Math.max(...points.map((point) => point.traffic), 1);

  const scaledFlows = points.map((point, index) => ({
    x: padding.left + (index / Math.max(points.length - 1, 1)) * chartWidth,
    y: padding.top + chartHeight - (point.flows / flowMax) * chartHeight,
  }));

  const scaledTraffic = points.map((point, index) => ({
    x: padding.left + (index / Math.max(points.length - 1, 1)) * chartWidth,
    y: padding.top + chartHeight - (point.traffic / trafficMax) * chartHeight,
  }));

  const flowPath = buildPath(scaledFlows);
  const areaPath = `${flowPath} L ${scaledFlows[scaledFlows.length - 1].x} ${padding.top + chartHeight} L ${scaledFlows[0].x} ${padding.top + chartHeight} Z`;
  const trafficPath = buildPath(scaledTraffic);

  const labels = [0, 0.33, 0.66, 1].map((ratio) => {
    const y = padding.top + chartHeight - ratio * chartHeight;
    return `<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}"></line>`;
  });

  const dateLabels = points
    .filter((_, index) => index === 0 || index === points.length - 1 || index === Math.floor(points.length / 2))
    .map((point) => point.timestamp)
    .filter((value, index, array) => array.indexOf(value) === index)
    .map((timestamp, index, array) => {
      const ratio = array.length === 1 ? 0.5 : index / (array.length - 1);
      const x = padding.left + ratio * chartWidth;
      return `<text x="${x}" y="${height - 8}" text-anchor="middle" class="chart-axis">${formatShortDate(timestamp)}</text>`;
    });

  el.activityChart.innerHTML = `
    <g class="chart-grid">${labels.join("")}</g>
    <path d="${areaPath}" class="chart-area"></path>
    <path d="${flowPath}" class="chart-line"></path>
    <path d="${trafficPath}" class="chart-line chart-line--sand"></path>
    ${dateLabels.join("")}
  `;

  const totalFlows = points.reduce((sum, item) => sum + item.flows, 0);
  const totalTraffic = points.reduce((sum, item) => sum + item.traffic, 0);
  el.activityChartMeta.textContent = `Trend built from ${points.length} time buckets, ${formatNumber(totalFlows)} total flows, and ${formatBytes(totalTraffic)} total traffic.`;
}

function buildPath(points) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`).join(" ");
}

function displayName(report, type, value) {
  if (!report.config.anonymizeNames) {
    return value;
  }
  return report.anonymizer(type, value);
}

function displayLocationLabel(report, location) {
  if (!location) {
    return "";
  }

  if (/site/i.test(location.dimension || "")) {
    return displayName(report, "site", location.label);
  }

  return location.label;
}

function describeLocationForNarrative(config, location) {
  if (!location) {
    return "the leading access location";
  }

  if (config.anonymizeNames && /site/i.test(location.dimension || "")) {
    return "a leading site location";
  }

  return location.label;
}

function createAnonymizer() {
  const buckets = new Map();
  const counters = new Map();

  return (type, value) => {
    const key = `${type}:${value}`;
    if (!buckets.has(key)) {
      const next = (counters.get(type) || 0) + 1;
      counters.set(type, next);
      const prefixMap = {
        user: "User",
        device: "Device",
        site: "Site",
      };
      buckets.set(key, `${prefixMap[type] || "Entity"} ${String(next).padStart(2, "0")}`);
    }
    return buckets.get(key);
  };
}

function tableMarkup(headers, rows) {
  return `
    <table class="data-table">
      <thead>
        <tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function barMarkup(percent, caption, tone = "emerald") {
  return `
    <div class="bar-track">
      <div class="bar-fill ${tone === "sand" ? "sand" : ""}" style="width:${percent}%"></div>
    </div>
    <div class="bar-caption">
      <span>${percent}%</span>
      <span>${escapeHtml(caption)}</span>
    </div>
  `;
}

function applicationSubnote(app) {
  const parts = [app.category || app.family || "AI", activityModeMeta[app.mode]?.label || "AI"];
  if (app.edition && app.edition !== "Unspecified") {
    parts.push(app.edition);
  }
  return parts.filter(Boolean).join(" · ");
}

function riskPill(riskLevel) {
  const label = String(riskLevel || "Unknown").toUpperCase();
  if (label === "LOW") {
    return `<span class="pill-yes">${escapeHtml(label)}</span>`;
  }
  if (label === "MEDIUM" || label === "UNKNOWN") {
    return `<span class="pill-mixed">${escapeHtml(label)}</span>`;
  }
  return `<span class="pill-no">${escapeHtml(label)}</span>`;
}

function statusPill(label) {
  if (label === "Approved" || label === "Sanctioned") {
    return `<span class="pill-yes">${escapeHtml(label)}</span>`;
  }
  if (label === "Review") {
    return `<span class="pill-mixed">${escapeHtml(label)}</span>`;
  }
  return `<span class="pill-no">${escapeHtml(label)}</span>`;
}

function paintBadge(node, text, tone) {
  node.textContent = text;
  node.className = `badge ${tone}`;
}

function setStatus(tone, text) {
  el.statusBanner.textContent = text;
  el.statusBanner.className = `status-banner ${tone}`;
}

function pressureLabel(value) {
  if (value >= 75) {
    return "High executive signal. This account shows enough unmanaged AI use or control activity to support an urgent governance discussion.";
  }
  if (value >= 45) {
    return "Moderate executive signal. Enough AI activity is visible to support a leadership conversation about governance and control.";
  }
  if (value > 0) {
    return "Early or concentrated AI footprint. The report still helps establish baseline visibility and policy need.";
  }
  return "Load an assessment to calculate the current exposure signal.";
}

function toneColor(value) {
  if (value >= 75) {
    return "var(--danger)";
  }
  if (value >= 45) {
    return "var(--sand)";
  }
  return "var(--brand)";
}

function editionColor(edition) {
  switch (String(edition || "").toLowerCase()) {
    case "enterprise":
      return "linear-gradient(90deg, #0f7f5a, #2ec08e)";
    case "paid":
      return "linear-gradient(90deg, #d18f33, #f3b46f)";
    case "free":
      return "linear-gradient(90deg, #6c8b80, #a8bab3)";
    case "api / platform":
      return "linear-gradient(90deg, #9b4a39, #d7755d)";
    default:
      return "linear-gradient(90deg, #8aa399, #b8c9c3)";
  }
}

function powerShellEscape(value) {
  return String(value || "").replace(/'/g, "''");
}

function toPowerShellArray(items) {
  const values = Array.isArray(items) ? items : [];
  if (!values.length) {
    return "@()";
  }
  return `@(${values.map((item) => `'${powerShellEscape(item)}'`).join(", ")})`;
}

function exportReport() {
  if (!currentReport) {
    setStatus("warn", "Load an assessment before exporting JSON.");
    return;
  }

  const payload = {
    exportedAt: new Date().toISOString(),
    config: {
      accountLabel: currentReport.config.accountLabel,
      accountId: currentReport.config.accountId,
      endpoint: currentReport.config.endpoint,
      startDate: currentReport.config.startDate,
      endDate: currentReport.config.endDate,
      approvedApps: currentReport.config.approvedApps,
      trackedApps: currentReport.config.trackedApps,
      anonymizeNames: currentReport.config.anonymizeNames,
      includeDetectionSignals: currentReport.config.includeDetectionSignals,
      executiveContext: currentReport.config.executiveContext,
    },
    summary: {
      pressureIndex: currentReport.pressureIndex,
      totals: currentReport.totals,
      shadowShare: currentReport.shadowShare,
      detectionCount: currentReport.detectionCount,
      governance: currentReport.governance,
      warnings: currentReport.warnings,
    },
    apps: currentReport.apps,
    meaningfulEditions: currentReport.meaningfulEditions,
    users: currentReport.users,
    devices: currentReport.devices,
    sites: currentReport.sites,
    locations: currentReport.locations,
    detections: currentReport.detections,
    promptMetadata: currentReport.promptMetadata,
    promptIntelligence: currentReport.promptIntelligence,
    promptToolApps: currentReport.promptToolApps,
    activityModes: currentReport.activityModes,
    valueProofs: currentReport.valueProofs,
    narrative: currentReport.reportText,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  const safeName = normalize(currentReport.config.accountLabel || "cato-ai-assessment") || "cato-ai-assessment";
  link.href = URL.createObjectURL(blob);
  link.download = `${safeName}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function renderPowerShellSnippet() {
  if (!el.powerShellCode) {
    return;
  }

  const endpoint = computeEndpoint(state.apiPrefix);
  const accountLabel = state.accountLabel.trim() || "Customer Assessment";
  const accountId = state.accountId.trim() || "<ACCOUNT_ID>";
  const startDate = state.startDate || toInputDate(new Date());
  const endDate = state.endDate || startDate;
  const outputName = normalize(state.accountLabel.trim() || `cato-ai-${accountId}`) || "cato-ai-assessment";
  const approvedApps = toPowerShellArray(parseList(state.approvedApps));
  const trackedApps = toPowerShellArray(parseList(state.trackedApps));
  const includeDetections = state.includeDetectionSignals ? "$true" : "$false";
  const promptFocusFamilies = toPowerShellArray(
    unique(appClassificationProfiles.filter((item) => item.promptFocus).map((item) => item.family)),
  );
  const script = `# Cato AI Security Visibility Assessment - PowerShell collector
# Paste into Windows PowerShell or PowerShell 7, then press Enter to accept the defaults shown in brackets.
# The collector writes one JSON file per dataset plus a combined assessment export so the results can be inspected or shared.
# Raw prompt text is not exposed in this API path; the optional prompt section focuses on topic and intent metadata where available.
# If the supplied endpoint override fails, the collector automatically retries the shared Cato GraphQL endpoint.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$defaults = @{
  AccountLabel = '${powerShellEscape(accountLabel)}'
  AccountId = '${powerShellEscape(accountId)}'
  Endpoint = '${powerShellEscape(endpoint)}'
  StartDate = '${powerShellEscape(startDate)}'
  EndDate = '${powerShellEscape(endDate)}'
  IncludeDetections = ${includeDetections}
  ApprovedApps = ${approvedApps}
  AiDiscoveryHints = ${trackedApps}
  PromptFocusFamilies = ${promptFocusFamilies}
}

function Read-ValueOrDefault {
  param(
    [string]$Prompt,
    [string]$Default
  )
  if ([string]::IsNullOrWhiteSpace($Default)) {
    return (Read-Host $Prompt).Trim()
  }
  $value = Read-Host "$Prompt [$Default]"
  if ([string]::IsNullOrWhiteSpace($value)) {
    return $Default
  }
  return $value.Trim()
}

function Read-YesNo {
  param(
    [string]$Prompt,
    [bool]$Default = $true
  )
  $hint = if ($Default) { 'Y/n' } else { 'y/N' }
  $value = Read-Host "$Prompt [$hint]"
  if ([string]::IsNullOrWhiteSpace($value)) {
    return $Default
  }
  return @('y', 'yes', 'true', '1').Contains($value.Trim().ToLowerInvariant())
}

function Resolve-CatoEndpoint {
  param([string]$Value)
  $trimmed = ($Value | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    return '${powerShellEscape(defaultEndpoint)}'
  }
  if ($trimmed -notmatch '^https?://') {
    if ($trimmed -match 'catonetworks\\.com') {
      $trimmed = "https://$trimmed"
    } else {
      return "https://api.$trimmed.catonetworks.com/api/v1/graphql2"
    }
  }
  $uri = [Uri]$trimmed
  if ([string]::IsNullOrWhiteSpace($uri.AbsolutePath) -or $uri.AbsolutePath -eq '/') {
    return "$($uri.Scheme)://$($uri.Host)/api/v1/graphql2"
  }
  if ($uri.AbsolutePath -notmatch '/api/v1/graphql2$') {
    return "$($uri.Scheme)://$($uri.Host)/api/v1/graphql2"
  }
  return "$($uri.Scheme)://$($uri.Host)$($uri.AbsolutePath)"
}

function New-TimeFrame {
  param(
    [string]$StartDate,
    [string]$EndDate
  )
  foreach ($value in @($StartDate, $EndDate)) {
    if ($value -notmatch '^\\d{4}-\\d{2}-\\d{2}$') {
      throw "Dates must use YYYY-MM-DD format."
    }
  }
  $start = [datetime]::ParseExact($StartDate, 'yyyy-MM-dd', $null)
  $end = [datetime]::ParseExact($EndDate, 'yyyy-MM-dd', $null)
  if ($end -lt $start) {
    throw 'End date must be the same as or later than the start date.'
  }
  return "utc.{$StartDate/00:00:00--$EndDate/23:59:59}"
}

function Get-EndpointCandidates {
  param([string]$PrimaryEndpoint)
  $candidates = @()
  foreach ($candidate in @($PrimaryEndpoint, '${powerShellEscape(defaultEndpoint)}')) {
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and -not $candidates.Contains($candidate)) {
      $candidates += $candidate
    }
  }
  return $candidates
}

function New-SafeFolderName {
  param([string]$Value)
  $clean = ($Value -replace '[^a-zA-Z0-9_-]+', '-').Trim('-')
  if ([string]::IsNullOrWhiteSpace($clean)) {
    return 'cato-ai-assessment'
  }
  return $clean
}

$collectorWarnings = New-Object 'System.Collections.Generic.List[string]'

function Add-CollectorWarning {
  param([string]$Message)
  [void]$collectorWarnings.Add($Message)
  Write-Host $Message -ForegroundColor DarkYellow
}

function Write-JsonArtifact {
  param(
    [string]$Name,
    $Data
  )
  $path = Join-Path $config.OutputDir "$Name.json"
  $Data | ConvertTo-Json -Depth 30 | Set-Content -Path $path -Encoding UTF8
  return $path
}

$accountLabel = Read-ValueOrDefault -Prompt 'Customer label' -Default $defaults.AccountLabel
$accountId = Read-ValueOrDefault -Prompt 'CMA account ID' -Default $defaults.AccountId
if ([string]::IsNullOrWhiteSpace($accountId)) {
  throw 'CMA account ID is required.'
}
$endpointInput = Read-ValueOrDefault -Prompt 'GraphQL endpoint or regional prefix' -Default $defaults.Endpoint
$startDate = Read-ValueOrDefault -Prompt 'Start date (YYYY-MM-DD)' -Default $defaults.StartDate
$endDate = Read-ValueOrDefault -Prompt 'End date (YYYY-MM-DD)' -Default $defaults.EndDate
$includeDetections = Read-YesNo -Prompt 'Run optional detections plus prompt topic/intent queries' -Default $defaults.IncludeDetections
$timeFrame = New-TimeFrame -StartDate $startDate -EndDate $endDate
$apiKey = Read-Host 'Paste the customer read-only Cato API key'
if ([string]::IsNullOrWhiteSpace($apiKey)) {
  throw 'API key is required.'
}

$resolvedEndpoint = Resolve-CatoEndpoint -Value $endpointInput
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputSeed = New-SafeFolderName -Value '${powerShellEscape(outputName)}'
$outputDir = Join-Path (Get-Location) "$outputSeed-$timestamp"
$null = New-Item -ItemType Directory -Path $outputDir -Force

$config = @{
  AccountLabel = $accountLabel
  AccountId = $accountId
  Endpoint = $resolvedEndpoint
  StartDate = $startDate
  EndDate = $endDate
  TimeFrame = $timeFrame
  IncludeDetections = $includeDetections
  ApprovedApps = $defaults.ApprovedApps
  AiDiscoveryHints = $defaults.AiDiscoveryHints
  PromptFocusFamilies = $defaults.PromptFocusFamilies
  OutputDir = $outputDir
}

Write-Host ''
Write-Host "Collecting AI visibility assessment for $($config.AccountLabel)" -ForegroundColor Cyan
Write-Host "Endpoint: $($config.Endpoint)" -ForegroundColor DarkCyan
Write-Host "Timeframe: $($config.StartDate) to $($config.EndDate)" -ForegroundColor DarkCyan
Write-Host "Output folder: $($config.OutputDir)" -ForegroundColor DarkCyan

$AppQuery = @'
${appQuery.trim()}
'@
$TimeSeriesQuery = @'
${appTimeSeriesQuery.trim()}
'@
$SnapshotQuery = @'
${snapshotQuery.trim()}
'@
$EventsQuery = @'
${eventsQuery.trim()}
'@

function Invoke-CatoGraphQL {
  param(
    [string]$Query,
    [hashtable]$Variables
  )
  $lastError = $null
  foreach ($candidate in (Get-EndpointCandidates -PrimaryEndpoint $config.Endpoint)) {
    try {
      $headers = @{
        'Content-Type' = 'application/json'
        'x-api-key' = $apiKey
      }
      $body = @{ query = $Query; variables = $Variables } | ConvertTo-Json -Depth 20
      $response = Invoke-RestMethod -Method Post -Uri $candidate -Headers $headers -Body $body
      if ($response.errors) {
        throw (($response.errors | ForEach-Object { $_.message }) -join '; ')
      }
      if ($candidate -ne $config.Endpoint) {
        $config.Endpoint = $candidate
        Add-CollectorWarning ("Primary endpoint failed, fell back to {0}" -f $candidate)
      }
      return $response.data
    } catch {
      $lastError = $_
    }
  }
  throw $lastError
}

function Get-CatoPagedAppStats {
  param(
    [string]$DimensionField,
    [array]$Measures,
    [array]$Filters = @(),
    [int]$Limit = 250,
    [int]$MaxRecords = 5000
  )
  $records = @()
  for ($offset = 0; $offset -lt $MaxRecords; $offset += $Limit) {
    $data = Invoke-CatoGraphQL -Query $AppQuery -Variables @{
      accountID = $config.AccountId
      timeFrame = $config.TimeFrame
      dimensions = @(@{ fieldName = $DimensionField })
      measures = $Measures
      filters = $Filters
      sort = @(@{ fieldName = 'traffic'; order = 'desc' })
      limit = $Limit
      from = $offset
    }
    $page = @($data.appStats.records | ForEach-Object { $_.fieldsMap })
    if ($page.Count -eq 0) {
      break
    }
    $records += $page
    if ($page.Count -lt $Limit) {
      break
    }
  }
  return $records
}

function Get-FirstWorkingAppStats {
  param(
    [string]$Label,
    [string[]]$DimensionFields,
    [array]$Measures,
    [array]$Filters = @(),
    [int]$Limit = 25,
    [int]$MaxRecords = 250,
    [switch]$Optional
  )
  $lastError = $null
  foreach ($dimensionField in $DimensionFields) {
    try {
      $records = Get-CatoPagedAppStats -DimensionField $dimensionField -Measures $Measures -Filters $Filters -Limit $Limit -MaxRecords $MaxRecords
      if ($records.Count -gt 0) {
        return @{ DimensionField = $dimensionField; Records = $records }
      }
    } catch {
      $lastError = $_
    }
  }
  if ($Optional) {
    if ($lastError) {
      Add-CollectorWarning ("{0} was not available: {1}" -f $Label, $lastError.Exception.Message)
    } else {
      Add-CollectorWarning ("{0} returned no records in this timeframe." -f $Label)
    }
    return @{ DimensionField = $DimensionFields[0]; Records = @() }
  }
  if ($lastError) {
    throw ("Unable to pull {0}. {1}" -f $Label, $lastError.Exception.Message)
  }
  return @{ DimensionField = $DimensionFields[0]; Records = @() }
}

function Try-GetEventsByDimensions {
  param(
    [array[]]$DimensionAttempts,
    [int]$Limit = 60
  )
  foreach ($dimensionSet in $DimensionAttempts) {
    try {
      $data = Invoke-CatoGraphQL -Query $EventsQuery -Variables @{
        accountID = $config.AccountId
        timeFrame = $config.TimeFrame
        measures = @(@{ fieldName = 'event_count'; aggType = 'sum' })
        dimensions = @($dimensionSet | ForEach-Object { @{ fieldName = $_ } })
        filters = @(
          @{ fieldName = 'event_type'; operator = 'is'; values = @('Security') },
          @{ fieldName = 'event_sub_type'; operator = 'in'; values = ${toPowerShellArray(detectionEventSubtypes)} }
        )
        sort = @(@{ fieldName = 'event_count'; order = 'desc' })
        limit = $Limit
        from = 0
      }
      $records = @($data.events.records | ForEach-Object { $_.fieldsMap })
      if ($records.Count -gt 0) {
        return @{ Dimensions = $dimensionSet; Records = $records }
      }
    } catch {
      Add-CollectorWarning ("Skipping events dimension set [{0}] because it was not exposed." -f ($dimensionSet -join ', '))
    }
  }
  return $null
}

$applicationMeasures = @(
  @{ fieldName = 'traffic'; aggType = 'sum' }
  @{ fieldName = 'flows_created'; aggType = 'sum' }
  @{ fieldName = 'risk_score'; aggType = 'max' }
  @{ fieldName = 'risk_level'; aggType = 'any' }
  @{ fieldName = 'sanctioned'; aggType = 'any' }
  @{ fieldName = 'category'; aggType = 'any' }
)
$entityMeasures = @(
  @{ fieldName = 'traffic'; aggType = 'sum' }
  @{ fieldName = 'flows_created'; aggType = 'sum' }
)

$applicationPull = Get-FirstWorkingAppStats -Label 'application analytics' -DimensionFields @('application_name', 'application') -Measures $applicationMeasures -Limit 250 -MaxRecords 5000
$applicationField = $applicationPull.DimensionField
$applicationRecords = @($applicationPull.Records)
$userMeasures = @(
  @{ fieldName = 'traffic'; aggType = 'sum' }
  @{ fieldName = 'flows_created'; aggType = 'sum' }
  @{ fieldName = $applicationField; aggType = 'count_distinct' }
)
$followUpAppNames = @($applicationRecords | ForEach-Object {
  if ($_.application_name) { $_.application_name } elseif ($_.application) { $_.application }
} | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique -First 75)
$appFilters = if ($followUpAppNames.Count -gt 0) {
  @(@{ fieldName = $applicationField; operator = 'in'; values = $followUpAppNames })
} else { @() }

$snapshot = $null
try {
  $snapshot = Invoke-CatoGraphQL -Query $SnapshotQuery -Variables @{ accountID = $config.AccountId }
} catch {
  Add-CollectorWarning ("Account snapshot was unavailable: {0}" -f $_.Exception.Message)
}

$timeSeries = $null
if ($followUpAppNames.Count -gt 0) {
  try {
    $timeSeries = Invoke-CatoGraphQL -Query $TimeSeriesQuery -Variables @{
      accountID = $config.AccountId
      timeFrame = $config.TimeFrame
      measures = @(
        @{ fieldName = 'flows_created'; aggType = 'sum' }
        @{ fieldName = 'traffic'; aggType = 'sum' }
      )
      filters = $appFilters
      buckets = 10
    }
  } catch {
    Add-CollectorWarning ("Timeseries analytics were unavailable: {0}" -f $_.Exception.Message)
  }
} else {
  Add-CollectorWarning 'Application analytics returned no app names to pivot into timeseries or entity ranking.'
}

$topUsers = if ($followUpAppNames.Count -gt 0) {
  Get-FirstWorkingAppStats -Label 'user analytics' -DimensionFields @('user_name', 'user', 'ad_name') -Measures $userMeasures -Filters $appFilters -Limit 20 -MaxRecords 100 -Optional
} else { @{ DimensionField = 'user_name'; Records = @() } }
$topDevices = if ($followUpAppNames.Count -gt 0) {
  Get-FirstWorkingAppStats -Label 'device analytics' -DimensionFields @('device_name', 'host_name') -Measures $entityMeasures -Filters $appFilters -Limit 15 -MaxRecords 100 -Optional
} else { @{ DimensionField = 'device_name'; Records = @() } }
$topSites = if ($followUpAppNames.Count -gt 0) {
  Get-FirstWorkingAppStats -Label 'site analytics' -DimensionFields @('src_site_name', 'site_name') -Measures $entityMeasures -Filters $appFilters -Limit 15 -MaxRecords 100 -Optional
} else { @{ DimensionField = 'src_site_name'; Records = @() } }
$topLocations = if ($followUpAppNames.Count -gt 0) {
  Get-FirstWorkingAppStats -Label 'location analytics' -DimensionFields @('site_country', 'src_country_name', 'country', 'site_region', 'site_state', 'src_site_name', 'site_name') -Measures $entityMeasures -Filters $appFilters -Limit 15 -MaxRecords 100 -Optional
} else { @{ DimensionField = 'site_country'; Records = @() } }

$detections = @()
if ($config.IncludeDetections) {
  try {
    $detectionResponse = Invoke-CatoGraphQL -Query $EventsQuery -Variables @{
      accountID = $config.AccountId
      timeFrame = $config.TimeFrame
      measures = @(@{ fieldName = 'event_count'; aggType = 'sum' })
      dimensions = @(
        @{ fieldName = 'event_sub_type' }
        @{ fieldName = 'action' }
      )
      filters = @(
        @{ fieldName = 'event_type'; operator = 'is'; values = @('Security') }
        @{ fieldName = 'event_sub_type'; operator = 'in'; values = ${toPowerShellArray(detectionEventSubtypes)} }
      )
      sort = @(@{ fieldName = 'event_count'; order = 'desc' })
      limit = 30
      from = 0
    }
    $detections = @($detectionResponse.events.records | ForEach-Object { $_.fieldsMap })
  } catch {
    Add-CollectorWarning ("Detection analytics were unavailable: {0}" -f $_.Exception.Message)
  }
}

$promptMetadata = @()
$promptDimensions = @()
if ($config.IncludeDetections) {
  $promptAttempt = Try-GetEventsByDimensions -DimensionAttempts @(
    @('application', 'topic', 'intent', 'detection_name', 'action'),
    @('application_name', 'topic', 'intent', 'detection_name', 'action'),
    @('application', 'topic', 'intent', 'action'),
    @('application_name', 'topic', 'intent', 'action'),
    @('application', 'topic', 'action'),
    @('application_name', 'topic', 'action'),
    @('application', 'intent', 'action'),
    @('application_name', 'intent', 'action')
  ) -Limit 60
  if ($promptAttempt) {
    $promptMetadata = @($promptAttempt.Records)
    $promptDimensions = @($promptAttempt.Dimensions)
  } else {
    Add-CollectorWarning 'Prompt topic and intent dimensions were not exposed for this account or timeframe.'
  }
}

$summary = @{
  pulledAt = (Get-Date).ToString('o')
  applicationCount = @($applicationRecords).Count
  followUpAppCount = $followUpAppNames.Count
  userCount = @($topUsers.Records).Count
  deviceCount = @($topDevices.Records).Count
  siteCount = @($topSites.Records).Count
  locationCount = @($topLocations.Records).Count
  detectionCount = @($detections).Count
  promptMetadataCount = @($promptMetadata).Count
  applicationDimension = $applicationField
  userDimension = $topUsers.DimensionField
  deviceDimension = $topDevices.DimensionField
  siteDimension = $topSites.DimensionField
  locationDimension = $topLocations.DimensionField
  promptDimensions = @($promptDimensions)
  warnings = @($collectorWarnings)
}

$assessment = @{
  pulledAt = (Get-Date).ToString('o')
  config = $config
  summary = $summary
  applicationField = $applicationField
  applications = @($applicationRecords)
  snapshot = if ($snapshot) { $snapshot.accountSnapshot } else { $null }
  timeSeries = if ($timeSeries) { $timeSeries.appStatsTimeSeries } else { $null }
  topUsers = @($topUsers.Records)
  topDevices = @($topDevices.Records)
  topSites = @($topSites.Records)
  topLocations = @($topLocations.Records)
  detections = @($detections)
  promptMetadataDimensions = @($promptDimensions)
  promptMetadata = @($promptMetadata)
  warnings = @($collectorWarnings)
}

$writtenFiles = @(
  (Write-JsonArtifact -Name 'collector-config' -Data $config)
  (Write-JsonArtifact -Name 'summary' -Data $summary)
  (Write-JsonArtifact -Name 'applications' -Data $applicationRecords)
  (Write-JsonArtifact -Name 'time-series' -Data (if ($timeSeries) { $timeSeries.appStatsTimeSeries } else { $null }))
  (Write-JsonArtifact -Name 'snapshot' -Data (if ($snapshot) { $snapshot.accountSnapshot } else { $null }))
  (Write-JsonArtifact -Name 'top-users' -Data $topUsers)
  (Write-JsonArtifact -Name 'top-devices' -Data $topDevices)
  (Write-JsonArtifact -Name 'top-sites' -Data $topSites)
  (Write-JsonArtifact -Name 'top-locations' -Data $topLocations)
  (Write-JsonArtifact -Name 'detections' -Data $detections)
  (Write-JsonArtifact -Name 'prompt-metadata' -Data @{ dimensions = @($promptDimensions); records = @($promptMetadata) })
  (Write-JsonArtifact -Name 'assessment-export' -Data $assessment)
)

Write-Host ''
Write-Host ("Assessment export written to {0}" -f (Join-Path $config.OutputDir 'assessment-export.json')) -ForegroundColor Green
Write-Host ("Applications pulled: {0}" -f $applicationRecords.Count) -ForegroundColor Cyan
Write-Host ("Follow-up apps used for pivots: {0}" -f $followUpAppNames.Count) -ForegroundColor Cyan
Write-Host ("JSON files written: {0}" -f $writtenFiles.Count) -ForegroundColor Cyan
if ($collectorWarnings.Count -gt 0) {
  Write-Host ("Warnings returned: {0}" -f $collectorWarnings.Count) -ForegroundColor DarkYellow
  $collectorWarnings | ForEach-Object { Write-Host (" - {0}" -f $_) -ForegroundColor DarkYellow }
}`;

  el.powerShellCode.textContent = script;
}

async function copyPowerShellStarter() {
  const code = el.powerShellCode?.textContent?.trim();
  if (!code) {
    setStatus("warn", "There is no PowerShell collector to copy yet.");
    return;
  }

  await navigator.clipboard.writeText(code);
  setStatus("good", "PowerShell collector copied to the clipboard.");
}

async function copyNarrative() {
  if (!currentReport) {
    setStatus("warn", "Load an assessment before copying the narrative.");
    return;
  }
  await navigator.clipboard.writeText(currentReport.reportText.join("\n\n"));
  setStatus("good", "Executive narrative copied to the clipboard.");
}

function resetState() {
  Object.assign(state, buildDefaultState(), { apiKey: "" });
  saveState();
  currentReport = null;
  hydrateInputs();
  renderDefaultState();
  updateActionState();
  setStatus("neutral", "Inputs reset. Add the next customer API key and pull a new assessment.");
}

function toInputDate(date) {
  return date.toISOString().slice(0, 10);
}

function formatDateRange(start, end) {
  const options = { year: "numeric", month: "short", day: "numeric" };
  return `${new Date(`${start}T00:00:00`).toLocaleDateString(undefined, options)} to ${new Date(`${end}T00:00:00`).toLocaleDateString(undefined, options)}`;
}

function formatShortDate(timestamp) {
  return new Date(timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const scaled = bytes / 1024 ** power;
  return `${scaled.toFixed(scaled >= 100 || power === 0 ? 0 : scaled >= 10 ? 1 : 2)} ${units[power]}`;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatPercent(value) {
  return `${Math.round((Number(value) || 0) * 100)}%`;
}

function toNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function parseBoolean(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (value == null) {
    return null;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["true", "yes", "1"].includes(normalized)) {
    return true;
  }
  if (["false", "no", "0"].includes(normalized)) {
    return false;
  }
  return null;
}

function pickField(fieldsMap, candidates) {
  for (const candidate of candidates) {
    const exact = fieldsMap[candidate];
    if (exact != null && String(exact).trim()) {
      return String(exact).trim();
    }

    const fuzzyKey = Object.keys(fieldsMap).find((key) => normalize(key) === normalize(candidate) || normalize(key).includes(normalize(candidate)));
    if (fuzzyKey && fieldsMap[fuzzyKey] != null && String(fieldsMap[fuzzyKey]).trim()) {
      return String(fieldsMap[fuzzyKey]).trim();
    }
  }
  return "";
}

function titleCase(value) {
  return String(value || "")
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function normalize(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function unique(items) {
  return Array.from(new Set(items.filter(Boolean)));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

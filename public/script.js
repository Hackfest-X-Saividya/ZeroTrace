
const authPanel = document.getElementById("authPanel");
const authStatus = document.getElementById("authStatus");
const authForms = document.getElementById("authForms");
const signupForm = document.getElementById("signupForm");
const loginForm = document.getElementById("loginForm");
const loggedInPanel = document.getElementById("loggedInPanel");
const loggedInEmail = document.getElementById("loggedInEmail");
const logoutBtn = document.getElementById("logoutBtn");
const showLoginTab = document.getElementById("showLoginTab");
const showSignupTab = document.getElementById("showSignupTab");

const scanHistoryPanel = document.getElementById("scanHistoryPanel");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
const scanHistoryList = document.getElementById("scanHistoryList");
const historyStatus = document.getElementById("historyStatus");

const codeInput = document.getElementById("codeInput");
const scanBtn = document.getElementById("scanBtn");
const sampleBtn = document.getElementById("sampleBtn");
const scanStatus = document.getElementById("scanStatus");
const charCount = document.getElementById("charCount");
const resultBadge = document.getElementById("resultBadge");
const totalCount = document.getElementById("totalCount");
const highCount = document.getElementById("highCount");
const mediumCount = document.getElementById("mediumCount");
const results = document.getElementById("results");
const aiFixBtn = document.getElementById("aiFixBtn");
const aiFixStatus = document.getElementById("aiFixStatus");
const aiFixPanel = document.getElementById("aiFixPanel");
const aiFixSummary = document.getElementById("aiFixSummary");
const fixedCodeOutput = document.getElementById("fixedCodeOutput");
const applyFixBtn = document.getElementById("applyFixBtn");
const copyFixBtn = document.getElementById("copyFixBtn");
const downloadFixBtn = document.getElementById("downloadFixBtn");
const aiRescanPanel = document.getElementById("aiRescanPanel");
const syntaxStatus = document.getElementById("syntaxStatus");
const aiRescanStatus = document.getElementById("aiRescanStatus");
const aiRescanResults = document.getElementById("aiRescanResults");
const codeComparison = document.getElementById("codeComparison");
const originalCodeOutput = document.getElementById("originalCodeOutput");
const comparisonFixedCode = document.getElementById("comparisonFixedCode");
const diffOutput = document.getElementById("diffOutput");
const scannerWorkspace = document.getElementById("scannerWorkspace");
let currentFindings = [];
let proposedFix = "";
let originalCode = "";

const sampleCode = `function renderUser(userInput) {
  // Demo only: unsafe patterns for ZeroTrace to identify.
  eval(userInput);

  const output = document.getElementById("output");
  output.innerHTML = userInput;
}

const api_key = "DEMO_FAKE_KEY_123456789";
`;

function updateCharCount() {
  charCount.textContent = `${codeInput.value.length.toLocaleString()} characters`;
}
function renderDiff(original, fixed) {
  diffOutput.replaceChildren();

  const oldLines = original.split("\n");
  const newLines = fixed.split("\n");

  const rows = oldLines.length + 1;
  const cols = newLines.length + 1;

  // Avoid excessive memory use for very large files.
  if (rows * cols > 1_000_000) {
    diffOutput.textContent =
      "The files are too large for detailed comparison. " +
      "Review the Original code and AI-proposed code panels above.";
    return;
  }

  // Build the Longest Common Subsequence table.
  const dp = Array.from(
    { length: rows },
    () => new Uint32Array(cols)
  );

  for (let i = oldLines.length - 1; i >= 0; i--) {
    for (let j = newLines.length - 1; j >= 0; j--) {
      if (oldLines[i] === newLines[j]) {
        dp[i][j] = 1 + dp[i + 1][j + 1];
      } else {
        dp[i][j] = Math.max(
          dp[i + 1][j],
          dp[i][j + 1]
        );
      }
    }
  }

  // Reconstruct the changes in order.
  const changes = [];
  let i = 0;
  let j = 0;

  while (i < oldLines.length && j < newLines.length) {
    if (oldLines[i] === newLines[j]) {
      changes.push({
        type: "unchanged",
        text: oldLines[i]
      });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      changes.push({
        type: "removed",
        text: oldLines[i]
      });
      i++;
    } else {
      changes.push({
        type: "added",
        text: newLines[j]
      });
      j++;
    }
  }

  while (i < oldLines.length) {
    changes.push({
      type: "removed",
      text: oldLines[i++]
    });
  }

  while (j < newLines.length) {
    changes.push({
      type: "added",
      text: newLines[j++]
    });
  }

  // Render safely as text, not HTML.
  for (const change of changes) {
    const line = document.createElement("div");
    line.className = `diff-line ${change.type}`;

    const marker =
      change.type === "removed" ? "− " :
      change.type === "added" ? "+ " : "  ";

    line.textContent = marker + change.text;
    diffOutput.append(line);
  }
}
function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderFindings(findings) {
  results.replaceChildren();

  if (findings.length === 0) {
    const empty = makeElement("div", "empty-state");
    empty.append(
      makeElement("div", "empty-icon", "✓"),
      makeElement("h3", "", "No matching patterns found"),
      makeElement(
        "p",
        "",
        "The current rules did not identify any of their targeted patterns. This does not guarantee the code is secure."
      )
    );
    results.append(empty);
    return;
  }

  for (const finding of findings) {
    const card = makeElement("article", "finding");
    const top = makeElement("div", "finding-top");
    const titleGroup = document.createElement("div");

    titleGroup.append(
      makeElement("h3", "", finding.title),
      makeElement(
        "div",
        "finding-meta",
        `${finding.id} · Line ${finding.line}`
      )
    );

    const severity = makeElement(
      "span",
      `severity ${(finding.severity || "Low").toLowerCase()}`,
      finding.severity || "Unspecified"
    );

    top.append(titleGroup, severity);
    card.append(top);

    if (finding.evidence) {
      card.append(makeElement("code", "evidence", finding.evidence));
    }

    card.append(makeElement("p", "", finding.explanation));

    const recommendation = makeElement("p", "recommendation");
    recommendation.append(
      makeElement("strong", "", "Recommended action: "),
      document.createTextNode(finding.recommendation)
    );

    card.append(recommendation);
    results.append(card);
  }
}
async function rescanProposedCode(code) {
  aiRescanPanel.hidden = false;
  aiRescanStatus.textContent = "Scanning the proposed code...";
  aiRescanResults.replaceChildren();

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.message || "Security re-scan failed.");
    }

    syntaxStatus.textContent =
  "✓ JavaScript syntax is valid. The proposed code passed the backend parser check.";

    const findings = data.findings || [];

    if (findings.length === 0) {
      aiRescanStatus.textContent =
        "No matching patterns detected. This does not guarantee the code is secure.";

      return;
    }

    aiRescanStatus.textContent =
      `${findings.length} potential finding${findings.length === 1 ? "" : "s"} remain.`;

    for (const finding of findings) {
      const item = document.createElement("div");
      item.className = "finding";

      const title = document.createElement("h4");
      title.textContent =
        `${finding.severity || "Unspecified"} · ${finding.title}`;

      const location = document.createElement("p");
      location.textContent = `Line ${finding.line}`;

      const explanation = document.createElement("p");
      explanation.textContent = finding.explanation || "";

      item.append(title, location, explanation);
      aiRescanResults.append(item);
    }
  } catch (error) {
    aiRescanStatus.textContent =
      `Could not check proposed code: ${error.message}`;
  }
}
function showError(message) {
  results.replaceChildren();

  const error = makeElement("div", "empty-state");
  error.append(
    makeElement("h3", "", "Scan could not be completed"),
    makeElement("p", "", message)
  );

  results.append(error);
}

codeInput.addEventListener("input", updateCharCount);

sampleBtn.addEventListener("click", () => {
  codeInput.value = sampleCode;
  updateCharCount();
  scanStatus.textContent = "Demo sample loaded. Click Analyze source code.";
});

scanBtn.addEventListener("click", async () => {
  const code = codeInput.value;
  originalCode = code;

  if (!code.trim()) {
    scanStatus.textContent = "Paste some JavaScript code first.";
    codeInput.focus();
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = "Analyzing...";
  scanStatus.textContent = "Checking source code...";
  resultBadge.textContent = "Scanning";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.message || "The scan request failed.");
    }

    const findings = data.findings || [];
    currentFindings = findings;
    const high = findings.filter((item) => item.severity === "High").length;
    const medium = findings.filter((item) => item.severity === "Medium").length;

    totalCount.textContent = findings.length;
    highCount.textContent = high;
    mediumCount.textContent = medium;
    resultBadge.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;

    renderFindings(findings);
    scanStatus.textContent =
      `Analyzed ${data.scannedCharacters.toLocaleString()} characters. Review each finding before taking action.`;
  } catch (error) {
    resultBadge.textContent = "Error";
    scanStatus.textContent = "Unable to complete the scan.";
    showError(error.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = "<span>⌕</span> Analyze source code";
  }
});

updateCharCount();
aiFixBtn.addEventListener("click", async () => {
  const code = codeInput.value;

  if (!code.trim()) {
    aiFixStatus.textContent = "Paste JavaScript code first.";
    codeInput.focus();
    return;
  }

  aiFixBtn.disabled = true;
  aiFixBtn.textContent = "Generating fix...";
  aiFixStatus.textContent = "Asking Gemini to suggest a safer version...";
  aiFixPanel.hidden = true;

  try {
    const response = await fetch("/api/ai-fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        findings: currentFindings
      })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.message || "AI fix request failed.");
    }

    proposedFix = data.fixedCode;
fixedCodeOutput.value = data.fixedCode;
aiFixSummary.textContent = data.summary;

originalCodeOutput.value = originalCode;
comparisonFixedCode.value = data.fixedCode;

renderDiff(originalCode, data.fixedCode);

codeComparison.hidden = false;

aiFixPanel.hidden = false;
    aiFixStatus.textContent =
      "Proposed fix generated. Review it before using it.";
  } catch (error) {
    aiFixStatus.textContent = `AI Fix failed: ${error.message}`;
  } finally {
    aiFixBtn.disabled = false;
    aiFixBtn.textContent = "✨ AI Fix";
  }
});

applyFixBtn.addEventListener("click", () => {
  if (!proposedFix) return;

  codeInput.value = proposedFix;
  updateCharCount();
  scanStatus.textContent =
    "AI-proposed code placed in the editor. Analyze it again before using it.";
  codeInput.focus();
});

copyFixBtn.addEventListener("click", async () => {
  if (!proposedFix) return;

  try {
    await navigator.clipboard.writeText(proposedFix);
    aiFixStatus.textContent = "Proposed code copied to clipboard.";
  } catch {
    aiFixStatus.textContent =
      "Clipboard access failed. Select and copy the proposed code manually.";
  }
});
downloadFixBtn.addEventListener("click", () => {
  if (!proposedFix) {
    aiFixStatus.textContent = "Generate a fix before downloading.";
    return;
  }

  const blob = new Blob([proposedFix], {
    type: "text/javascript;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "zerotrace-fixed.js";

  document.body.append(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);

  aiFixStatus.textContent = "Download started: zerotrace-fixed.js";
});


async function refreshAuthState() {
  try {
    const response = await fetch("/api/auth/me", {
      credentials: "same-origin"
    });

    if (!response.ok) {
      authForms.hidden = false;
      loggedInPanel.hidden = true;
      scannerWorkspace.hidden = true;
      scanHistoryPanel.hidden = true;
      historyStatus.textContent = "";
      scanHistoryList.replaceChildren();
      return;
    }

    const data = await response.json();

    authForms.hidden = true;
    loggedInPanel.hidden = false;
    scannerWorkspace.hidden = false;
    scanHistoryPanel.hidden = false;

    loggedInEmail.textContent = data.user.email;
    authStatus.textContent = "You're logged in.";

    await loadScanHistory();
  } catch {
    authStatus.textContent = "Unable to check login status.";
  }
}


async function submitAuthForm(form, endpoint) {
  authStatus.textContent = "Please wait...";

  const formData = new FormData(form);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "same-origin",
      body: JSON.stringify({
        email: formData.get("email"),
        password: formData.get("password")
      })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      authStatus.textContent = data.message || "Authentication failed.";
      return;
    }

    form.reset();
    authStatus.textContent = data.message;
    await refreshAuthState();
  } catch {
    authStatus.textContent = "Unable to contact ZeroTrace.";
  }
}

signupForm.addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuthForm(signupForm, "/api/auth/signup");
});

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuthForm(loginForm, "/api/auth/login");
});

logoutBtn.addEventListener("click", async () => {
  authStatus.textContent = "Logging out...";

  try {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin"
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      authStatus.textContent = data.message || "Logout failed.";
      return;
    }

    authStatus.textContent = "Logged out successfully.";
    await refreshAuthState();
  } catch {
    authStatus.textContent = "Unable to contact ZeroTrace.";
  }
});

refreshAuthState();

function showAuthForm(mode) {
  const isLogin = mode === "login";

  loginForm.hidden = !isLogin;
  signupForm.hidden = isLogin;

  showLoginTab.classList.toggle("active", isLogin);
  showSignupTab.classList.toggle("active", !isLogin);

  showLoginTab.setAttribute("aria-selected", String(isLogin));
  showSignupTab.setAttribute("aria-selected", String(!isLogin));
}

showLoginTab.addEventListener("click", () => {
  showAuthForm("login");
});

showSignupTab.addEventListener("click", () => {
  showAuthForm("signup");
});

// Show the sign-in form by default.
showAuthForm("login");
async function loadScanHistory() {
  historyStatus.textContent = "Loading scan history...";
  scanHistoryList.replaceChildren();

  try {
    const response = await fetch("/api/scan-history");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Failed to load scan history.");
    }

    if (!data.history || data.history.length === 0) {
      historyStatus.textContent = "No scans yet. Run your first security scan!";
      return;
    }

    historyStatus.textContent = "";

    data.history.forEach((scan) => {
      const card = document.createElement("div");
      card.className = "history-card";

      const date = document.createElement("p");
      date.className = "history-date";
      date.textContent = new Date(scan.scannedAt).toLocaleString();

      const summary = document.createElement("p");
      summary.className = "history-summary";
      summary.textContent =
        `${scan.totalFindings} finding(s) · ${scan.scannedCharacters} characters scanned`;

      card.append(date, summary);

      if (Array.isArray(scan.findings) && scan.findings.length > 0) {
        const findingsList = document.createElement("ul");
        findingsList.className = "history-findings";

        scan.findings.forEach((finding) => {
          const item = document.createElement("li");
          item.textContent =
            `${finding.severity || "Unknown"} — ${finding.title || "Untitled finding"} (Line ${finding.line ?? "?"})`;
          findingsList.appendChild(item);
        });

        card.appendChild(findingsList);
      }

      scanHistoryList.appendChild(card);
    });
  } catch (error) {
    historyStatus.textContent = error.message;
  }
}

refreshHistoryBtn.addEventListener("click", loadScanHistory);
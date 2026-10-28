
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

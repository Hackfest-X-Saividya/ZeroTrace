
import express from "express";
import helmet from "helmet";
import path from "path";
import { fileURLToPath } from "url";
import { scanCode } from "./scanner/scanner.js";
import { analyzeAST } from "./scanner/astScanner.js";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "ZeroTrace backend is running." });
});

app.post("/api/scan", (req, res) => {
  const { code } = req.body ?? {};

  if (typeof code !== "string" || !code.trim()) {
    return res.status(400).json({
      success: false,
      message: "Please provide JavaScript source code to scan."
    });
  }

  if (code.length > 50000) {
    return res.status(413).json({
      success: false,
      message: "Code exceeds the 50,000-character limit."
    });
  }

  const astResult = analyzeAST(code);

  if (!astResult.success) {
    return res.status(400).json({
      success: false,
      message: astResult.message,
      findings: []
    });
  }

  const combined = [...astResult.findings, ...scanCode(code)];
  const seen = new Set();

  const findings = combined.filter((finding) => {
    const key = `${finding.title}:${finding.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const severityOrder = { High: 0, Medium: 1, Low: 2 };
  findings.sort(
    (a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity] ||
      a.line - b.line
  );

  res.json({
    success: true,
    scannedCharacters: code.length,
    totalFindings: findings.length,
    findings
  });
});

app.listen(PORT, () => {
  console.log(`ZeroTrace is running at http://localhost:${PORT}`);
});

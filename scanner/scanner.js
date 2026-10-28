
const rules = [
  {
    id: "JS001",
    title: "Dynamic code execution",
    severity: "High",
    pattern: /\beval\s*\(/g,
    explanation:
      "eval() executes a string as JavaScript. If untrusted input reaches it, an attacker may execute unintended code.",
    recommendation:
      "Avoid eval(). Use safer alternatives such as JSON.parse() when processing JSON."
  },
  {
    id: "JS002",
    title: "Potentially unsafe HTML insertion",
    severity: "Medium",
    pattern: /\.innerHTML\s*=/g,
    explanation:
      "Assigning untrusted content to innerHTML can introduce cross-site scripting (XSS).",
    recommendation:
      "Use textContent for plain text, or sanitize HTML with a trusted sanitizer."
  },
  {
    id: "JS003",
    title: "Hardcoded credential-like value",
    severity: "High",
    pattern:
      /\b(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*["'][^"']{6,}["']/gi,
    explanation:
      "A hardcoded value appears to contain a credential. This pattern alone cannot confirm whether it is genuine.",
    recommendation:
      "Remove real secrets from source code and use environment variables or a secret manager."
  }
];

export function scanCode(source) {
  const findings = [];

  for (const rule of rules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = pattern.exec(source)) !== null) {
      const line = source.slice(0, match.index).split("\n").length;

      findings.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        line,
        evidence: redactEvidence(match[0], rule.id),
        explanation: rule.explanation,
        recommendation: rule.recommendation
      });

      // Prevent an infinite loop if a future rule matches an empty string.
      if (match[0].length === 0) {
        pattern.lastIndex++;
      }
    }
  }

  return findings.sort((a, b) => a.line - b.line);
}

function redactEvidence(match, ruleId) {
  if (ruleId === "JS003") {
    // Hide quoted credential values before displaying evidence.
    return match.replace(/(["'])[^"']{6,}\1/g, '"[REDACTED]"');
  }

  return match;
}

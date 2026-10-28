
import { parse } from "acorn";

export function analyzeAST(source) {
  const findings = [];
  let ast;

  try {
    ast = parse(source, {
      ecmaVersion: "latest",
      sourceType: "script",
      locations: true
    });
  } catch (error) {
    return {
      success: false,
      message: `Unable to parse JavaScript: ${error.message}`,
      findings: []
    };
  }

  function visit(node) {
    if (!node || typeof node !== "object") return;

    // Detect calls such as eval(userInput).
    if (
      node.type === "CallExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "eval"
    ) {
      findings.push({
        id: "AST001",
        title: "Dynamic code execution",
        severity: "High",
        line: node.loc.start.line,
        evidence: "eval(...)",
        explanation:
          "The AST identifies a call to eval(). If untrusted input reaches this call, it may execute unintended JavaScript.",
        recommendation:
          "Avoid eval() and use a safer alternative appropriate to the task."
      });
    }

    // Detect assignments to element.innerHTML.
    if (
      node.type === "AssignmentExpression" &&
      node.left.type === "MemberExpression" &&
      !node.left.computed &&
      node.left.property.name === "innerHTML"
    ) {
      findings.push({
        id: "AST002",
        title: "Potentially unsafe HTML insertion",
        severity: "Medium",
        line: node.loc.start.line,
        evidence: "element.innerHTML = ...",
        explanation:
          "The AST identifies an assignment to innerHTML. If the assigned content is untrusted, this may create an XSS risk.",
        recommendation:
          "Use textContent for plain text, or sanitize HTML with a trusted sanitizer."
      });
    }

    // Recursively inspect child nodes.
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === "string") {
            visit(child);
          }
        }
      } else if (value && typeof value.type === "string") {
        visit(value);
      }
    }
  }

  visit(ast);

  return {
    success: true,
    findings
  };
}

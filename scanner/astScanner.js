
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

  function addFinding(node, finding) {
    findings.push({
      ...finding,
      line: node.loc.start.line
    });
  }

  function visit(node) {
    if (!node || typeof node !== "object") return;

    // AST001: Detect eval(...)
    if (
      node.type === "CallExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "eval"
    ) {
      addFinding(node, {
        id: "AST001",
        title: "Dynamic code execution",
        severity: "High",
        evidence: "eval(...)",
        explanation:
          "Calling eval() executes JavaScript represented as a string. If untrusted input reaches it, an attacker may influence the executed code.",
        recommendation:
          "Avoid eval(). Use explicit parsing or safer alternatives appropriate to the task."
      });
    }

    // AST002: Detect assignments such as element.innerHTML = ...
    if (
      node.type === "AssignmentExpression" &&
      node.left.type === "MemberExpression" &&
      !node.left.computed &&
      node.left.property.name === "innerHTML"
    ) {
      addFinding(node, {
        id: "AST002",
        title: "Potentially unsafe HTML insertion",
        severity: "Medium",
        evidence: "element.innerHTML = ...",
        explanation:
          "Assigning content to innerHTML can introduce cross-site scripting (XSS) if the content contains untrusted HTML.",
        recommendation:
          "Use textContent for plain text, or sanitize HTML with a trusted sanitizer before insertion."
      });
    }

    // AST003: Detect new Function(...)
    if (
      node.type === "NewExpression" &&
      node.callee.type === "Identifier" &&
      node.callee.name === "Function"
    ) {
      addFinding(node, {
        id: "AST003",
        title: "Dynamic function construction",
        severity: "High",
        evidence: "new Function(...)",
        explanation:
          "The Function constructor creates executable JavaScript from strings. Dynamically constructed code can be dangerous when influenced by untrusted input.",
        recommendation:
          "Avoid constructing executable code from strings. Use ordinary functions and explicit data handling."
      });
    }

    // AST004: Detect document.write(...)
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      !node.callee.computed &&
      node.callee.property.name === "write" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "document"
    ) {
      addFinding(node, {
        id: "AST004",
        title: "Potentially unsafe document.write()",
        severity: "Medium",
        evidence: "document.write(...)",
        explanation:
          "document.write() inserts content into the document. If untrusted input is written as HTML, it may introduce an XSS risk.",
        recommendation:
          "Prefer DOM methods such as createElement() and textContent, and avoid inserting untrusted HTML."
      });
    }

    // AST005: Detect compound assignments such as element.innerHTML += ...
    if (
      node.type === "AssignmentExpression" &&
      node.operator !== "=" &&
      node.left.type === "MemberExpression" &&
      !node.left.computed &&
      node.left.property.name === "innerHTML"
    ) {
      addFinding(node, {
        id: "AST005",
        title: "Potentially unsafe HTML modification",
        severity: "Medium",
        evidence: "element.innerHTML += ...",
        explanation:
          "A compound assignment to innerHTML can insert HTML into the DOM. Untrusted content may create an XSS risk.",
        recommendation:
          "Use textContent for plain text or sanitize any HTML with a trusted sanitizer."
      });
    }

    // AST006: Detect potentially risky child_process API calls.
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "child_process" &&
      !node.callee.computed &&
      ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"].includes(
        node.callee.property.name
      )
    ) {
      addFinding(node, {
        id: "AST006",
        title: "Potentially risky command execution",
        severity: "High",
        evidence: `child_process.${node.callee.property.name}(...)`,
        explanation:
          "This call can execute operating-system commands or programs. If untrusted input reaches command arguments, it may create a command-injection risk.",
        recommendation:
          "Avoid passing untrusted input to shell commands. Prefer fixed executables, argument arrays, input validation, and shell:false where supported."
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


import { parse } from "acorn";

const COMMAND_FUNCTIONS = [
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "execFile",
  "execFileSync"
];

export function analyzeAST(source) {
  const findings = [];
  const importedCommandFunctions = new Set();
  const requiredCommandObjects = new Set();
  let ast;

  try {
    ast = parse(source, {
      ecmaVersion: "latest",
      sourceType: "module",
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

  // First pass: identify command functions imported from child_process.
  for (const node of ast.body) {
    if (
      node.type === "ImportDeclaration" &&
      ["child_process", "node:child_process"].includes(node.source.value)
    ) {
      for (const specifier of node.specifiers) {
        if (
          specifier.type === "ImportSpecifier" &&
          COMMAND_FUNCTIONS.includes(specifier.imported.name)
        ) {
          importedCommandFunctions.add(specifier.local.name);
        }

        if (specifier.type === "ImportNamespaceSpecifier") {
          requiredCommandObjects.add(specifier.local.name);
        }

        if (specifier.type === "ImportDefaultSpecifier") {
          requiredCommandObjects.add(specifier.local.name);
        }
      }
    }

    // CommonJS: const { exec: runCommand } = require("child_process")
    if (node.type === "VariableDeclaration") {
      for (const declaration of node.declarations) {
        const init = declaration.init;

        if (
          init?.type !== "CallExpression" ||
          init.callee.type !== "Identifier" ||
          init.callee.name !== "require" ||
          init.arguments.length !== 1 ||
          init.arguments[0].type !== "Literal" ||
          !["child_process", "node:child_process"].includes(
            init.arguments[0].value
          )
        ) {
          continue;
        }

        if (declaration.id.type === "ObjectPattern") {
          for (const property of declaration.id.properties) {
            if (
              property.type === "Property" &&
              !property.computed &&
              property.key.type === "Identifier" &&
              COMMAND_FUNCTIONS.includes(property.key.name)
            ) {
              const localName =
                property.value.type === "Identifier"
                  ? property.value.name
                  : property.value.left?.name;

              if (localName) {
                importedCommandFunctions.add(localName);
              }
            }
          }
        } else if (declaration.id.type === "Identifier") {
          requiredCommandObjects.add(declaration.id.name);
        }
      }
    }
  }

  function visit(node) {
    if (!node || typeof node !== "object") return;

    // AST001: eval(...)
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
          "eval() executes JavaScript represented as a string. Untrusted input may influence the executed code.",
        recommendation:
          "Avoid eval(). Use explicit parsing or safer alternatives."
      });
    }

    // AST002: innerHTML = ...
    if (
      node.type === "AssignmentExpression" &&
      node.left.type === "MemberExpression" &&
      node.left.property.name === "innerHTML"
    ) {
      addFinding(node, {
        id: "AST002",
        title: "Potentially unsafe HTML insertion",
        severity: "Medium",
        evidence: "element.innerHTML = ...",
        explanation:
          "Assigning untrusted HTML to innerHTML may introduce cross-site scripting (XSS).",
        recommendation:
          "Use textContent for plain text or sanitize HTML with a trusted sanitizer."
      });
    }

    // AST003: new Function(...)
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
          "The Function constructor creates executable JavaScript from strings.",
        recommendation:
          "Avoid constructing executable code from strings."
      });
    }

    // AST004: document.write(...)
    if (
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "document" &&
      !node.callee.computed &&
      node.callee.property.name === "write"
    ) {
      addFinding(node, {
        id: "AST004",
        title: "Potentially unsafe document.write()",
        severity: "Medium",
        evidence: "document.write(...)",
        explanation:
          "Writing untrusted content into the document may introduce an XSS risk.",
        recommendation:
          "Prefer safe DOM methods such as createElement() and textContent."
      });
    }

    // AST005: compound innerHTML assignments.
    // AST002 already detects the same assignment expression, so avoid a duplicate.
    if (
      node.type === "AssignmentExpression" &&
      node.operator !== "=" &&
      node.left.type === "MemberExpression" &&
      node.left.property.name === "innerHTML"
    ) {
      addFinding(node, {
        id: "AST005",
        title: "Potentially unsafe HTML modification",
        severity: "Medium",
        evidence: "element.innerHTML += ...",
        explanation:
          "A compound innerHTML assignment may insert untrusted HTML into the DOM.",
        recommendation:
          "Use textContent for plain text or sanitize HTML with a trusted sanitizer."
      });
    }

    // AST006: direct, imported, and namespace command-execution calls.
    if (node.type === "CallExpression") {
      let commandName = null;
      let isCommandCall = false;

      if (
        node.callee.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.property.type === "Identifier" &&
        COMMAND_FUNCTIONS.includes(node.callee.property.name)
      ) {
        const object = node.callee.object;

        if (
          object.type === "Identifier" &&
          (object.name === "child_process" ||
            requiredCommandObjects.has(object.name))
        ) {
          commandName = node.callee.property.name;
          isCommandCall = true;
        }
      } else if (
        node.callee.type === "Identifier" &&
        importedCommandFunctions.has(node.callee.name)
      ) {
        commandName = node.callee.name;
        isCommandCall = true;
      }

      if (isCommandCall) {
       
        addFinding(node, {
          id: "AST006",
          title: "Command execution API usage",
          severity: "Medium",
          evidence: `${commandName}(...)`,
          explanation:
            "This call uses an API capable of executing operating-system commands. This is not necessarily a vulnerability; risk depends on how the command and its arguments are constructed and whether untrusted input can influence them.",
          recommendation:
            "Review the command and its arguments. Avoid shell execution with untrusted input; prefer fixed executables, validated arguments, and shell:false where supported."
        });

      }
    }

    // Recursively inspect child nodes.
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === "string") visit(child);
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

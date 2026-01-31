import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Execute shell commands
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-002: Command Injection - uses exec() without sanitization
 * - SEC-008: Missing Timeouts - no execution timeout
 * - SEC-009: Insecure Error Handling - exposes full error details
 */
export async function executeCommand(command: string) {
  console.error(`Executing command: ${command}`);

  try {
    // 🚨 SEC-002: Command Injection Vulnerability
    // Using exec() allows shell metacharacters and command chaining
    // Attacker could input: "ls && cat /etc/passwd"
    // Or: "npm install; rm -rf / --no-preserve-root"
    // Should use execFile() or proper input sanitization
    
    // 🚨 SEC-008: Missing Timeouts
    // No timeout means long-running commands can cause DoS
    // A command like "sleep 999999" would hang indefinitely
    const { stdout, stderr } = await execAsync(command);

    // 🚨 SEC-004: Information Disclosure
    // Logging command output may contain sensitive data
    console.error("Command output:", stdout);
    if (stderr) {
      console.error("Command stderr:", stderr);
    }

    return {
      content: [
        {
          type: "text",
          text: `Command executed successfully:\n\nOutput:\n${stdout}\n${
            stderr ? `\nErrors:\n${stderr}` : ""
          }`,
        },
      ],
    };
  } catch (error: any) {
    // 🚨 SEC-009: Insecure Error Handling
    // Exposing full error details including system paths and environment info
    console.error("Command execution failed:", error);
    
    return {
      content: [
        {
          type: "text",
          text: `Command execution failed:\n\nError: ${error.message}\n\nStdout: ${error.stdout}\n\nStderr: ${error.stderr}\n\nCode: ${error.code}`,
        },
      ],
      isError: true,
    };
  }
}

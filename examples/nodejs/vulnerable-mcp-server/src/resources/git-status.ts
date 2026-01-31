import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Git status resource handler
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-004: Information Disclosure - exposes repository details
 * - SEC-001: Missing Authorization - no access control
 */
export async function getGitStatus() {
  // 🚨 SEC-001: Missing Authorization
  // Anyone can read git status without authentication
  // May reveal sensitive branch names, file paths, etc.
  
  console.error("Fetching git status");

  try {
    // Get git status
    const { stdout: status } = await execAsync("git status");
    
    // Get current branch
    const { stdout: branch } = await execAsync("git branch --show-current");
    
    // Get recent commits
    const { stdout: log } = await execAsync("git log --oneline -10");
    
    // Get remote URL
    const { stdout: remote } = await execAsync("git remote get-url origin");

    // 🚨 SEC-004: Information Disclosure
    // Git remote URL may contain access tokens
    // Example: https://ghp_token123:x-oauth-basic@github.com/user/repo.git
    console.error("Git remote URL:", remote.trim());

    const gitInfo = {
      status: status.trim(),
      branch: branch.trim(),
      recentCommits: log.trim(),
      remote: remote.trim(), // May contain embedded tokens
      timestamp: new Date().toISOString(),
    };

    // 🚨 SEC-004: Logging potentially sensitive git info
    console.error("Git info:", JSON.stringify(gitInfo, null, 2));

    return {
      contents: [
        {
          uri: "project://git/status",
          mimeType: "application/json",
          text: JSON.stringify(gitInfo, null, 2),
        },
      ],
    };
  } catch (error: any) {
    // 🚨 SEC-009: Insecure Error Handling
    console.error("Git status error:", error);
    
    return {
      contents: [
        {
          uri: "project://git/status",
          mimeType: "application/json",
          text: JSON.stringify({
            error: error.message,
            stderr: error.stderr,
            stdout: error.stdout,
          }, null, 2),
        },
      ],
    };
  }
}

import { readFile } from "fs/promises";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Application logs resource handler
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-004: Information Disclosure - logs contain sensitive data
 * - SEC-001: Missing Authorization - no access control
 * - SEC-003: Input Validation - no log sanitization
 */
export async function getLogs() {
  // 🚨 SEC-001: Missing Authorization
  // Anyone can read application logs without authentication
  // Logs often contain sensitive debugging information
  
  console.error("Reading application logs");

  const logs: any = {
    timestamp: new Date().toISOString(),
    sources: {},
  };

  try {
    // Read application log file
    try {
      const appLog = await readFile("app.log", "utf-8");
      // 🚨 SEC-004: Application logs may contain:
      // - User passwords in failed login attempts
      // - API keys in request headers
      // - Database connection strings
      // - Personal user information (PII)
      // - Stack traces with sensitive paths
      logs.sources.application = appLog.split("\n").slice(-100).join("\n"); // Last 100 lines
      
      console.error("Application log size:", appLog.length);
    } catch (error) {
      logs.sources.application = "Log file not found";
    }

    // Read npm debug log
    try {
      const npmLog = await readFile("npm-debug.log", "utf-8");
      // 🚨 SEC-004: npm logs may contain:
      // - Registry authentication tokens
      // - Full system paths
      // - Environment variables
      logs.sources.npm = npmLog.split("\n").slice(-50).join("\n");
    } catch (error) {
      logs.sources.npm = "No npm debug log";
    }

    // Get system logs (on Unix systems)
    try {
      const { stdout } = await execAsync("tail -100 /var/log/syslog 2>/dev/null || tail -100 /var/log/system.log 2>/dev/null || echo 'System log not accessible'");
      // 🚨 SEC-004: System logs may contain:
      // - Authentication attempts with usernames
      // - Network configuration details
      // - Service credentials
      logs.sources.system = stdout;
    } catch (error) {
      logs.sources.system = "Not available";
    }

    // Create sample sensitive logs for demonstration
    logs.sources.example_sensitive_logs = `
[2024-01-29 10:15:23] INFO: User login attempt - email: john@example.com, password: MyPassword123!
[2024-01-29 10:15:24] ERROR: Database connection failed - Connection string: postgresql://admin:SuperSecret123@db.internal:5432/prod
[2024-01-29 10:15:25] DEBUG: API Request - Authorization: Bearer sk-proj-abc123def456ghi789
[2024-01-29 10:15:26] INFO: Payment processed - CC: 4532-1234-5678-9010, CVV: 123, Amount: $299.99
[2024-01-29 10:15:27] ERROR: Failed to encrypt - AES key: 5up3rS3cr3tK3y123456789
[2024-01-29 10:15:28] DEBUG: User data: {"ssn": "123-45-6789", "dob": "1990-01-01", "income": 75000}
[2024-01-29 10:15:29] INFO: AWS credentials refreshed - AccessKeyId: AKIAIOSFODNN7EXAMPLE, SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
[2024-01-29 10:15:30] ERROR: Exception in user service: ${new Error("Sample error").stack}
[2024-01-29 10:15:31] DEBUG: Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9.secret
[2024-01-29 10:15:32] INFO: Email sent - SMTP: smtp://user:emailpass123@mail.server.com:587
    `.trim();

    // 🚨 SEC-004: CRITICAL - Logging the logs (meta!)
    // This creates a recursive disclosure issue
    console.error("Logs content preview:", JSON.stringify(logs).substring(0, 500));

    return {
      contents: [
        {
          uri: "project://logs",
          mimeType: "text/plain",
          text: JSON.stringify(logs, null, 2),
        },
      ],
    };
  } catch (error: any) {
    console.error("Logs reading error:", error);
    
    return {
      contents: [
        {
          uri: "project://logs",
          mimeType: "text/plain",
          text: `Error reading logs: ${error.message}\n\nPartial logs:\n${JSON.stringify(logs, null, 2)}`,
        },
      ],
    };
  }
}

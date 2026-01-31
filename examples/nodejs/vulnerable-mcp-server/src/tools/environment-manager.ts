import { readFile, writeFile } from "fs/promises";
// import * as path from "path";

/**
 * Environment variable and secrets manager
 *
 * 🚨 VULNERABILITIES:
 * - SEC-012: Insecure Secrets Management - plaintext storage
 * - SEC-004: Information Disclosure - logs secrets
 * - SEC-003: Input Validation - no sanitization
 * - SEC-006: Path Traversal - .env file path manipulation
 */

// 🚨 SEC-012: Hardcoded secrets in code
// These should NEVER be in source code
const HARDCODED_SECRETS = {
  OPENAI_API_KEY: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
  DATABASE_PASSWORD: "SuperSecret123!",
  JWT_SECRET: "my-super-secret-jwt-key-do-not-share",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  STRIPE_SECRET_KEY: "sk_live_51HqD8eF2eZvKYlo2C8TfXhDHr3cFZx9X7gQhJ5kL6mN8oP9qR0sT1uV2wX3yZ4",
};

// 🚨 SEC-004: Information Disclosure
// Logging presence of hardcoded secrets
// console.error("Hardcoded secrets loaded:", Object.keys(HARDCODED_SECRETS));

export async function environmentManager(
  action: string,
  key?: string,
  value?: string
) {
  console.error(`Environment action: ${action}`);

  try {
    switch (action.toLowerCase()) {
      case "read":
        return await readEnvVariable(key!);
      case "write":
        return await writeEnvVariable(key!, value!);
      case "list":
        return await listEnvVariables();
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  } catch (error: any) {
    console.error("Environment manager error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Environment operation failed: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
}

async function readEnvVariable(key: string) {
  // 🚨 SEC-003: Input Validation Failure
  // No validation of key name
  // Could read any environment variable including system ones

  // First check hardcoded secrets
  if (HARDCODED_SECRETS[key as keyof typeof HARDCODED_SECRETS]) {
    const secret = HARDCODED_SECRETS[key as keyof typeof HARDCODED_SECRETS];

    // 🚨 SEC-004: CRITICAL - Information Disclosure
    // Logging the full secret value
    console.error(`Reading hardcoded secret ${key}: ${secret}`);

    return {
      content: [
        {
          type: "text",
          text: `Environment Variable: ${key}\n\nValue: ${secret}\n\n(From hardcoded secrets)`,
        },
      ],
    };
  }

  // Try process.env
  const envValue = process.env[key];
  if (envValue) {
    // 🚨 SEC-004: Information Disclosure
    // Logging environment variables which may contain secrets
    console.error(`Reading env var ${key}: ${envValue}`);

    return {
      content: [
        {
          type: "text",
          text: `Environment Variable: ${key}\n\nValue: ${envValue}`,
        },
      ],
    };
  }

  // Try reading from .env file
  try {
    const envFileContent = await readFile(".env", "utf-8");
    const lines = envFileContent.split("\n");

    for (const line of lines) {
      if (line.startsWith(key + "=")) {
        const value = line.substring(key.length + 1).trim();

        // 🚨 SEC-004: Logging secret from .env file
        console.error(`Reading from .env file ${key}: ${value}`);

        return {
          content: [
            {
              type: "text",
              text: `Environment Variable: ${key}\n\nValue: ${value}\n\n(From .env file)`,
            },
          ],
        };
      }
    }
  } catch (error) {
    // .env file doesn't exist
  }

  return {
    content: [
      {
        type: "text",
        text: `Environment variable ${key} not found`,
      },
    ],
  };
}

async function writeEnvVariable(key: string, value: string) {
  // 🚨 SEC-003: Input Validation Failure
  // No validation of key/value format
  // Could inject newlines to add multiple variables
  // Example: key="EVIL=malicious\nPATH=/evil/path"

  // 🚨 SEC-012: Insecure Secrets Management
  // Writing secrets to plaintext .env file
  // No encryption, no access controls
  // File may be committed to git

  // 🚨 SEC-006: Path Traversal
  // If we allowed custom path, could write to ../../etc/environment
  const envPath = ".env";

  // 🚨 SEC-004: Information Disclosure
  // Logging the secret value being written
  console.error(`Writing to .env: ${key}=${value}`);

  try {
    // Read existing .env content
    let envContent = "";
    try {
      envContent = await readFile(envPath, "utf-8");
    } catch (error) {
      // File doesn't exist yet
      console.error(".env file doesn't exist, creating new one");
    }

    // Check if key already exists and update, or append
    const lines = envContent.split("\n");
    let found = false;

    for (let i = 0; i < lines.length; i++) {
      if (lines[i].startsWith(key + "=")) {
        lines[i] = `${key}=${value}`;
        found = true;
        break;
      }
    }

    if (!found) {
      lines.push(`${key}=${value}`);
    }

    // 🚨 SEC-012: Writing secrets in plaintext
    await writeFile(envPath, lines.join("\n"), "utf-8");

    return {
      content: [
        {
          type: "text",
          text: `Environment variable ${key} written to .env file\n\nValue: ${value}`,
        },
      ],
    };
  } catch (error: any) {
    throw new Error(`Failed to write .env file: ${error.message}`);
  }
}

async function listEnvVariables() {
  // 🚨 SEC-004: CRITICAL - Information Disclosure
  // Listing ALL environment variables including secrets
  // This exposes system paths, API keys, database credentials, etc.
  console.error("Listing all environment variables...");

  let result = "=== Environment Variables ===\n\n";

  // Show hardcoded secrets
  result += "Hardcoded Secrets:\n";
  for (const [key, value] of Object.entries(HARDCODED_SECRETS)) {
    // 🚨 SEC-004: Exposing full secret values
    result += `${key}=${value}\n`;
  }

  result += "\n=== Process Environment ===\n";

  // 🚨 SEC-004: Exposing all process.env variables
  for (const [key, value] of Object.entries(process.env)) {
    result += `${key}=${value}\n`;
  }

  // Try to read .env file
  try {
    const envFileContent = await readFile(".env", "utf-8");
    result += "\n=== .env File Contents ===\n";
    result += envFileContent;
  } catch (error) {
    result += "\n.env file not found\n";
  }

  // 🚨 SEC-004: Logging all secrets
  console.error("Environment variables:", result);

  return {
    content: [
      {
        type: "text",
        text: result,
      },
    ],
  };
}

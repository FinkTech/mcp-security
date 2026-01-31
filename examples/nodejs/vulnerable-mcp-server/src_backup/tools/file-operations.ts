import { readFile, writeFile } from "fs/promises";
import { exec } from "child_process";
import { promisify } from "util";
// import * as path from "path";

const execAsync = promisify(exec);

/**
 * File operations: read, write, search
 *
 * 🚨 VULNERABILITIES:
 * - SEC-006: Path Traversal - no path validation
 * - SEC-003: Input Validation - no sanitization of file content
 * - SEC-004: Information Disclosure - may expose sensitive files
 */

export async function fileOperations(
  operation: string,
  filePath: string,
  content?: string
) {
  console.log(`File operation: ${operation} on ${filePath}`);

  try {
    switch (operation) {
      case "read":
        return await readFileOperation(filePath);
      case "write":
        return await writeFileOperation(filePath, content || "");
      case "search":
        return await searchFileOperation(filePath, content || "");
      default:
        throw new Error(`Unknown operation: ${operation}`);
    }
  } catch (error: any) {
    console.error("File operation error:", error);
    return {
      content: [
        {
          type: "text",
          text: `File operation failed: ${error.message}\n\nStack: ${error.stack}`,
        },
      ],
      isError: true,
    };
  }
}

async function readFileOperation(filePath: string) {
  // 🚨 SEC-006: Path Traversal Vulnerability
  // No validation of file path - attacker can use ../../../etc/passwd
  // Should validate path is within allowed directories
  // Should normalize path and check against whitelist

  // 🚨 SEC-003: Input Validation Failure
  // No check for file extension or type
  // Could read binary files, executables, or system files

  const fileContent = await readFile(filePath, "utf-8");

  // 🚨 SEC-004: Information Disclosure
  // Logging file content may expose sensitive data like API keys
  console.log(`Read file ${filePath}, size: ${fileContent.length} bytes`);

  return {
    content: [
      {
        type: "text",
        text: `File: ${filePath}\n\nContent:\n${fileContent}`,
      },
    ],
  };
}

async function writeFileOperation(filePath: string, content: string) {
  // 🚨 SEC-006: Path Traversal Vulnerability
  // Attacker could write to ../../../etc/cron.d/malicious
  // Or overwrite critical system files

  // 🚨 SEC-003: Input Validation Failure
  // No sanitization of content
  // Could inject malicious code into config files or scripts
  // No file size limits - could cause disk space DoS

  await writeFile(filePath, content, "utf-8");

  console.log(`Wrote ${content.length} bytes to ${filePath}`);

  return {
    content: [
      {
        type: "text",
        text: `Successfully wrote to ${filePath}\n\nBytes written: ${content.length}`,
      },
    ],
  };
}

async function searchFileOperation(filePath: string, searchTerm: string) {
  // 🚨 SEC-002: Command Injection
  // Using grep via shell without sanitizing searchTerm
  // Attacker could inject: "test; cat /etc/passwd"

  // 🚨 SEC-006: Path Traversal
  // No validation of filePath

  const command = `grep -n "${searchTerm}" "${filePath}"`;

  console.log(`Searching in ${filePath} for: ${searchTerm}`);

  try {
    const { stdout } = await execAsync(command);

    return {
      content: [
        {
          type: "text",
          text: `Search results in ${filePath}:\n\n${stdout}`,
        },
      ],
    };
  } catch (error: any) {
    // Grep returns exit code 1 when no matches found
    if (error.code === 1) {
      return {
        content: [
          {
            type: "text",
            text: `No matches found for "${searchTerm}" in ${filePath}`,
          },
        ],
      };
    }

    throw error;
  }
}

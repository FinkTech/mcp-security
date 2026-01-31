import { readFile } from "fs/promises";

/**
 * Project files resource handler
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-006: Path Traversal - no path validation
 * - SEC-004: Information Disclosure - can read sensitive files
 * - SEC-001: Missing Authorization - no access control
 */
export async function getProjectFiles(path: string) {
  // 🚨 SEC-001: Missing Authorization
  // No check if user should have access to this file
  // No authentication or permission system
  
  // 🚨 SEC-006: CRITICAL - Path Traversal Vulnerability
  // Path is not validated or sanitized
  // Attacker could use: "../../../etc/passwd"
  // Or: "../../.env" to read secrets
  // Or: "../../../home/user/.ssh/id_rsa" to steal SSH keys
  // Should validate path is within project directory
  
  console.log(`Reading project file: ${path}`);

  try {
    // 🚨 SEC-004: Information Disclosure
    // Reading ANY file without restrictions
    // Could expose .env, database files, SSH keys, etc.
    const content = await readFile(path, "utf-8");
    
    // Logging file content (may contain secrets)
    console.log(`File content (${path}):`, content.substring(0, 200));

    return {
      contents: [
        {
          uri: `project://files/${path}`,
          mimeType: "text/plain",
          text: content,
        },
      ],
    };
  } catch (error: any) {
    // 🚨 SEC-009: Insecure Error Handling
    // Error message reveals if file exists and path details
    console.error(`Failed to read file ${path}:`, error);
    
    return {
      contents: [
        {
          uri: `project://files/${path}`,
          mimeType: "text/plain",
          text: `Error reading file: ${error.message}\n\nPath: ${path}\n\nError code: ${error.code}`,
        },
      ],
    };
  }
}
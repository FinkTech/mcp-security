import { readFile } from "fs/promises";

/**
 * Configuration files resource handler
 * 
 * 🚨 VULNERABILITIES:
 * - SEC-012: Insecure Secrets Management - exposes .env files
 * - SEC-004: Information Disclosure - leaks API keys and credentials
 * - SEC-001: Missing Authorization - no access control
 */
export async function getConfig() {
  // 🚨 SEC-001: Missing Authorization
  // No authentication required to access configuration
  // Anyone can read sensitive config files
  
  console.log("Reading project configuration");

  const config: any = {};

  try {
    // 🚨 SEC-012 & SEC-004: CRITICAL - Reading .env file with secrets
    // .env files contain API keys, database credentials, etc.
    // These should never be exposed via API
    try {
      const envContent = await readFile(".env", "utf-8");
      config.env = envContent;
      
      // 🚨 SEC-004: Logging .env contents
      console.log(".env file contents:", envContent);
    } catch (error) {
      config.env = "File not found";
    }

    // Read package.json
    try {
      const packageJson = await readFile("package.json", "utf-8");
      config.packageJson = JSON.parse(packageJson);
      
      // 🚨 SEC-004: Package.json may contain private registry credentials
      console.log("package.json loaded");
    } catch (error) {
      config.packageJson = "File not found";
    }

    // Read tsconfig.json
    try {
      const tsConfig = await readFile("tsconfig.json", "utf-8");
      config.tsconfig = JSON.parse(tsConfig);
    } catch (error) {
      config.tsconfig = "File not found";
    }

    // 🚨 SEC-012: Reading git config with potential tokens
    try {
      const gitConfig = await readFile(".git/config", "utf-8");
      config.gitConfig = gitConfig;
      
      // 🚨 SEC-004: Git config may have remote URLs with embedded tokens
      // Example: url = https://ghp_token@github.com/user/repo.git
      console.log("Git config:", gitConfig);
    } catch (error) {
      config.gitConfig = "File not found";
    }

    // 🚨 SEC-012: Reading AWS credentials
    try {
      const awsConfig = await readFile(
        `${process.env.HOME}/.aws/credentials`,
        "utf-8"
      );
      config.awsCredentials = awsConfig;
      
      // 🚨 SEC-004: CRITICAL - Exposing AWS credentials
      console.log("AWS credentials found");
    } catch (error) {
      config.awsCredentials = "File not found";
    }

    // 🚨 SEC-012: Reading SSH keys
    try {
      const sshKey = await readFile(
        `${process.env.HOME}/.ssh/id_rsa`,
        "utf-8"
      );
      config.sshPrivateKey = sshKey;
      
      // 🚨 SEC-004: CRITICAL - Exposing SSH private key
      console.log("SSH private key found");
    } catch (error) {
      config.sshPrivateKey = "File not found";
    }

    // Add some helpful metadata
    config.metadata = {
      readAt: new Date().toISOString(),
      hostname: process.env.HOSTNAME,
      user: process.env.USER,
      home: process.env.HOME,
      // 🚨 SEC-004: Exposing system paths
      pwd: process.cwd(),
    };

    return {
      contents: [
        {
          uri: "project://config",
          mimeType: "application/json",
          text: JSON.stringify(config, null, 2),
        },
      ],
    };
  } catch (error: any) {
    console.error("Config reading error:", error);
    
    return {
      contents: [
        {
          uri: "project://config",
          mimeType: "application/json",
          text: JSON.stringify({
            error: error.message,
            partialConfig: config,
          }, null, 2),
        },
      ],
    };
  }
}
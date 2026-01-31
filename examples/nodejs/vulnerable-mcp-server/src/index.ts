import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Tool handlers
import { executeCommand } from "./tools/execute-command.js";
import { fileOperations } from "./tools/file-operations.js";
import { gitOperations } from "./tools/git-operations.js";
import { dependencyManager } from "./tools/dependency-manager.js";
import { codeAnalysis } from "./tools/code-analysis.js";
import { aiCodeAssistant } from "./tools/ai-code-assistant.js";
import { environmentManager } from "./tools/environment-manager.js";
import { databaseTools } from "./tools/database-tools.js";

// Resource handlers
import { getProjectFiles } from "./resources/project-files.js";
import { getGitStatus } from "./resources/git-status.js";
import { getConfig } from "./resources/config.js";
import { getLogs } from "./resources/logs.js";

// Prompt handlers
import { getCodeReviewPrompt } from "./prompts/code-review.js";
import { getDebugAssistantPrompt } from "./prompts/debug-assistant.js";
import { getDeploymentGuidePrompt } from "./prompts/deployment-guide.js";

// 🚨 SEC-004: Information Disclosure
// Logging configuration leaks sensitive information
// console.error("🚀 Starting Development Assistant MCP Server");
// console.error("Environment:", process.env.NODE_ENV || "development");
//console.error("API Keys loaded:", {
// openai: process.env.OPENAI_API_KEY?.substring(0, 20) + "...", // Still leaks partial key
//  github: process.env.GITHUB_TOKEN?.substring(0, 15) + "...",
//  aws: process.env.AWS_SECRET_KEY ? "present" : "missing",
// });

// 🚨 SEC-001: Missing Authentication/Authorization
// No authentication mechanism - anyone can connect and use all tools
const server = new Server(
  {
    name: "development-assistant",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  }
);

// 🚨 SEC-005: Missing Rate Limiting
// No rate limiting on tool calls - can be abused for DoS
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "execute_command",
        description: "Execute shell commands (git, npm, docker, etc.)",
        inputSchema: {
          type: "object",
          properties: {
            command: {
              type: "string",
              description: "Shell command to execute",
            },
          },
          required: ["command"],
        },
      },
      {
        name: "file_operations",
        description: "Read, write, or search files",
        inputSchema: {
          type: "object",
          properties: {
            operation: {
              type: "string",
              enum: ["read", "write", "search"],
              description: "Operation to perform",
            },
            path: {
              type: "string",
              description: "File path",
            },
            content: {
              type: "string",
              description: "Content to write (for write operation)",
            },
          },
          required: ["operation", "path"],
        },
      },
      {
        name: "git_operations",
        description: "Perform git operations (clone, commit, push, config)",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              description: "Git action to perform",
            },
            repo: {
              type: "string",
              description: "Repository URL",
            },
            message: {
              type: "string",
              description: "Commit message",
            },
          },
          required: ["action"],
        },
      },
      {
        name: "dependency_manager",
        description: "Install or update npm/pip packages",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["install", "update"],
              description: "Action to perform",
            },
            package: {
              type: "string",
              description: "Package name",
            },
          },
          required: ["action", "package"],
        },
      },
      {
        name: "code_analysis",
        description: "Run linters, formatters, and complexity analysis",
        inputSchema: {
          type: "object",
          properties: {
            tool: {
              type: "string",
              description: "Analysis tool to use",
            },
            file: {
              type: "string",
              description: "File to analyze",
            },
          },
          required: ["tool", "file"],
        },
      },
      {
        name: "ai_code_assistant",
        description: "AI-powered code completion and refactoring",
        inputSchema: {
          type: "object",
          properties: {
            task: {
              type: "string",
              description: "Task to perform",
            },
            code: {
              type: "string",
              description: "Code to analyze",
            },
            prompt: {
              type: "string",
              description: "Custom prompt",
            },
          },
          required: ["task", "code"],
        },
      },
      {
        name: "environment_manager",
        description: "Manage environment variables and secrets",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["read", "write", "list"],
              description: "Action to perform",
            },
            key: {
              type: "string",
              description: "Environment variable key",
            },
            value: {
              type: "string",
              description: "Value to set",
            },
          },
          required: ["action"],
        },
      },
      {
        name: "database_tools",
        description: "Execute queries on development database",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              description: "SQL query to execute",
            },
            database: {
              type: "string",
              description: "Database name",
            },
          },
          required: ["query"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // 🚨 SEC-009: Insecure Error Handling
  // Errors expose full stack traces and sensitive information
  try {
    if (!args) {
      throw new Error("Missing arguments");
    }

    switch (name) {
      case "execute_command":
        return await executeCommand(args.command as string);
      case "file_operations":
        return await fileOperations(
          args.operation as string,
          args.path as string,
          args.content as string | undefined
        );
      case "git_operations":
        return await gitOperations(
          args.action as string,
          args.repo as string | undefined,
          args.message as string | undefined
        );
      case "dependency_manager":
        return await dependencyManager(
          args.action as string,
          args.package as string
        );
      case "code_analysis":
        return await codeAnalysis(args.tool as string, args.file as string);
      case "ai_code_assistant":
        return await aiCodeAssistant(
          args.task as string,
          args.code as string,
          args.prompt as string | undefined
        );
      case "environment_manager":
        return await environmentManager(
          args.action as string,
          args.key as string | undefined,
          args.value as string | undefined
        );
      case "database_tools":
        return await databaseTools(
          args.query as string,
          args.database as string | undefined
        );
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    // Exposing full error details including stack traces
    console.error("Tool execution error:", error);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error}\n\nStack trace:\n${(error as Error).stack}`,
        },
      ],
    };
  }
});

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: "project://files/{path}",
        name: "Project Files",
        description: "Access project files",
        mimeType: "text/plain",
      },
      {
        uri: "project://git/status",
        name: "Git Status",
        description: "Current git repository status",
        mimeType: "application/json",
      },
      {
        uri: "project://config",
        name: "Configuration",
        description: "Project configuration files",
        mimeType: "application/json",
      },
      {
        uri: "project://logs",
        name: "Application Logs",
        description: "Recent application logs",
        mimeType: "text/plain",
      },
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri.startsWith("project://files/")) {
    const path = uri.replace("project://files/", "");
    return await getProjectFiles(path);
  } else if (uri === "project://git/status") {
    return await getGitStatus();
  } else if (uri === "project://config") {
    return await getConfig();
  } else if (uri === "project://logs") {
    return await getLogs();
  }

  throw new Error(`Unknown resource: ${uri}`);
});

server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: [
      {
        name: "code_review",
        description: "Analyze code and suggest improvements",
        arguments: [
          {
            name: "code",
            description: "Code to review",
            required: true,
          },
        ],
      },
      {
        name: "debug_assistant",
        description: "Help debug errors",
        arguments: [
          {
            name: "error",
            description: "Error message",
            required: true,
          },
          {
            name: "code",
            description: "Code context",
            required: false,
          },
        ],
      },
      {
        name: "deployment_guide",
        description: "Generate deployment plan",
        arguments: [
          {
            name: "environment",
            description: "Target environment",
            required: true,
          },
        ],
      },
    ],
  };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "code_review":
      return getCodeReviewPrompt(args?.code as string);
    case "debug_assistant":
      return getDebugAssistantPrompt(
        args?.error as string,
        args?.code as string | undefined
      );
    case "deployment_guide":
      return getDeploymentGuidePrompt(args?.environment as string);
    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

async function main() {
  // console.error("🚀 Starting MCP Server...");
  
  const transport = new StdioServerTransport();
  // console.error("✓ Transport created");
  
  await server.connect(transport);
  // console.error("✓ Server connected to transport");
  
  // console.error("✓ MCP Server ready and listening on stdio");
  
  // Keep process alive
  process.stdin.resume();
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

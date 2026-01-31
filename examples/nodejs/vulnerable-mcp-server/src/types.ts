/**
 * Shared TypeScript types for the MCP server
 */

export interface ToolResponse {
  content: Array<{
    type: string;
    text: string;
  }>;
  isError?: boolean;
}

export interface ResourceResponse {
  contents: Array<{
    uri: string;
    mimeType: string;
    text: string;
  }>;
}

export interface PromptResponse {
  messages: Array<{
    role: string;
    content: {
      type: string;
      text: string;
    };
  }>;
}

export interface DatabaseConfig {
  sqlite: string;
  postgres: string;
  mysql: string;
}

export interface GitInfo {
  status: string;
  branch: string;
  recentCommits: string;
  remote: string;
  timestamp: string;
}

export interface LogSources {
  timestamp: string;
  sources: {
    application?: string;
    npm?: string;
    system?: string;
    example_sensitive_logs?: string;
  };
}

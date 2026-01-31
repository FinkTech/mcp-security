// test-minimal.js
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({ name: "test", version: "1.0.0" }, { capabilities: {} });

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Minimal test server ready");
}

main();

import { spawn } from "node:child_process";
import type { ServerConfig, MCPToolDef } from "../types.js";

const CONNECT_TIMEOUT_MS = 15000;

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: { tools?: MCPToolDef[]; [key: string]: unknown };
  error?: { code: number; message: string };
}

function makeRequest(method: string, id: number, params?: Record<string, unknown>): string {
  const msg: JsonRpcRequest = { jsonrpc: "2.0", id, method };
  if (params) msg.params = params;
  return JSON.stringify(msg) + "\n";
}

function makeNotification(method: string, params?: Record<string, unknown>): string {
  const msg: JsonRpcNotification = { jsonrpc: "2.0", method };
  if (params) msg.params = params;
  return JSON.stringify(msg) + "\n";
}

async function connectStdio(config: ServerConfig): Promise<MCPToolDef[]> {
  if (!config.command) {
    throw new Error(`Server "${config.name}" has no command defined`);
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Connection to "${config.name}" timed out after ${CONNECT_TIMEOUT_MS}ms`));
    }, CONNECT_TIMEOUT_MS);

    const child = spawn(config.command!, config.args ?? [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...config.env },
    });

    let buffer = "";
    let initDone = false;

    child.stdout.on("data", (data: Buffer) => {
      buffer += data.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line) as JsonRpcResponse;
          if (msg.id === 1 && msg.result) {
            initDone = true;
            child.stdin.write(makeNotification("notifications/initialized"));
            child.stdin.write(makeRequest("tools/list", 2));
          }
          if (msg.id === 2 && msg.result) {
            clearTimeout(timeout);
            const tools = msg.result.tools ?? [];
            child.kill();
            resolve(tools);
          }
          if (msg.error) {
            clearTimeout(timeout);
            child.kill();
            reject(new Error(`Server error: ${msg.error.message}`));
          }
        } catch {
          // non-JSON output, ignore
        }
      }
    });

    child.stderr.on("data", (data: Buffer) => {
      // stderr is informational, log but don't fail
      process.stderr.write(`  [${config.name} stderr] ${data.toString()}`);
    });

    child.on("error", (err) => {
      clearTimeout(timeout);
      reject(new Error(`Failed to spawn "${config.name}": ${err.message}`));
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      if (!initDone) {
        reject(new Error(`Server "${config.name}" exited with code ${code} before initialization`));
      }
    });

    child.stdin.write(
      makeRequest("initialize", 1, {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcpscan", version: "1.0.0" },
      }),
    );
  });
}

async function connectHttp(config: ServerConfig): Promise<MCPToolDef[]> {
  if (!config.url) {
    throw new Error(`Server "${config.name}" has no URL defined`);
  }

  const baseUrl = config.url.replace(/\/+$/, "");

  const initResponse = await fetch(`${baseUrl}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcpscan", version: "1.0.0" },
      },
    }),
  });

  if (!initResponse.ok) {
    throw new Error(`HTTP ${initResponse.status} from "${config.name}"`);
  }

  await fetch(`${baseUrl}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }),
  });

  const toolsResponse = await fetch(`${baseUrl}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    }),
  });

  if (!toolsResponse.ok) {
    throw new Error(`HTTP ${toolsResponse.status} from "${config.name}" on tools/list`);
  }

  const result = (await toolsResponse.json()) as JsonRpcResponse;
  if (result.error) {
    throw new Error(`Server error: ${result.error.message}`);
  }

  return result.result?.tools ?? [];
}

export async function connectToServer(config: ServerConfig): Promise<MCPToolDef[]> {
  switch (config.transport) {
    case "stdio":
      return connectStdio(config);
    case "http":
    case "sse":
      return connectHttp(config);
    default:
      throw new Error(`Unsupported transport: ${config.transport}`);
  }
}

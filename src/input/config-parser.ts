import { readFileSync } from "node:fs";
import type { ServerConfig, MCPToolDef } from "../types.js";

interface RawConfig {
  mcpServers?: Record<string, RawServerEntry>;
  servers?: RawServerEntry[];
  _test_tools?: Record<string, RawToolDef[]>;
  [key: string]: unknown;
}

interface RawServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  transport?: string;
  env?: Record<string, string>;
  [key: string]: unknown;
}

interface RawToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

function inferTransport(entry: RawServerEntry): "stdio" | "sse" | "http" {
  if (entry.transport === "sse") return "sse";
  if (entry.transport === "http") return "http";
  if (entry.url) {
    if (entry.url.includes("/sse")) return "sse";
    return "http";
  }
  return "stdio";
}

export function parseConfigFile(filePath: string): ServerConfig[] {
  const raw = readFileSync(filePath, "utf-8");
  const config: RawConfig = JSON.parse(raw);
  return parseConfig(config);
}

export function parseConfig(config: RawConfig): ServerConfig[] {
  const servers: ServerConfig[] = [];

  if (config.mcpServers && typeof config.mcpServers === "object") {
    for (const [name, entry] of Object.entries(config.mcpServers)) {
      servers.push({
        name,
        transport: inferTransport(entry),
        command: entry.command,
        args: entry.args,
        url: entry.url,
        env: entry.env,
      });
    }
  }

  if (Array.isArray(config.servers)) {
    for (const entry of config.servers) {
      const name = (entry as Record<string, unknown>).name as string ?? "unnamed";
      servers.push({
        name,
        transport: inferTransport(entry),
        command: entry.command,
        args: entry.args,
        url: entry.url,
        env: entry.env,
      });
    }
  }

  return servers;
}

export function parseTestTools(filePath: string): Record<string, MCPToolDef[]> {
  const raw = readFileSync(filePath, "utf-8");
  const config: RawConfig = JSON.parse(raw);
  const result: Record<string, MCPToolDef[]> = {};

  if (config._test_tools && typeof config._test_tools === "object") {
    for (const [serverName, tools] of Object.entries(config._test_tools)) {
      result[serverName] = tools.map((t) => ({
        name: t.name,
        description: t.description ?? "",
        inputSchema: t.inputSchema as MCPToolDef["inputSchema"],
      }));
    }
  }

  return result;
}

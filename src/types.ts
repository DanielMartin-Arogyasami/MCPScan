export type Transport = "stdio" | "sse" | "http";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ServerConfig {
  name: string;
  transport: Transport;
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

export interface MCPToolDef {
  name: string;
  description: string;
  inputSchema?: {
    type: string;
    properties?: Record<
      string,
      {
        type?: string;
        description?: string;
        enum?: string[];
        [key: string]: unknown;
      }
    >;
    required?: string[];
    [key: string]: unknown;
  };
}

export interface ScanTarget {
  server: ServerConfig;
  tools: MCPToolDef[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  message: string;
  toolName?: string;
  evidence?: string;
  fix?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  check(target: ScanTarget): Finding[];
}

export interface ScanResult {
  server: ServerConfig;
  tools: MCPToolDef[];
  findings: Finding[];
  score: number;
  grade: string;
  scannedAt: string;
  scanDurationMs: number;
  rulesRun: number;
}

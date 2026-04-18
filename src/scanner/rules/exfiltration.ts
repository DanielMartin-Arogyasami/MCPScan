import type { Rule, ScanTarget, Finding } from "../../types.js";

const READ_PATTERNS = [
  /\bread_file\b/i,
  /\bget_file\b/i,
  /\bfile_read\b/i,
  /\bquery_database\b/i,
  /\bsql_query\b/i,
  /\bread_database\b/i,
  /\bget_secret\b/i,
  /\bread_env\b/i,
  /\blist_credentials\b/i,
  /\bget_credentials\b/i,
];

const SEND_PATTERNS = [
  /\bsend_email\b/i,
  /\bhttp_request\b/i,
  /\bfetch_url\b/i,
  /\bupload_file\b/i,
  /\bpost_data\b/i,
  /\bwebhook\b/i,
  /\bsend_message\b/i,
  /\bapi_call\b/i,
  /\btransfer_file\b/i,
  /\bwrite_url\b/i,
];

const ENCODE_PATTERNS = [
  /\bbase64_encode\b/i,
  /\bencode\b/i,
  /\bcompress\b/i,
  /\bencrypt\b/i,
  /\bserialize\b/i,
];

export const exfiltrationRule: Rule = {
  id: "EXFIL",
  name: "Data Exfiltration Chain Detection",
  description: "Detects tool combinations that could be used to read and exfiltrate sensitive data",

  check(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    let counter = 1;
    const toolNames = target.tools.map((t) => t.name);

    const readTools = toolNames.filter((n) => READ_PATTERNS.some((p) => p.test(n)));
    const sendTools = toolNames.filter((n) => SEND_PATTERNS.some((p) => p.test(n)));
    const encodeTools = toolNames.filter((n) => ENCODE_PATTERNS.some((p) => p.test(n)));

    if (readTools.length > 0 && sendTools.length > 0) {
      findings.push({
        ruleId: `EXFIL-${String(counter++).padStart(3, "0")}`,
        ruleName: "Data exfiltration chain",
        severity: "CRITICAL",
        message: "Server has both data-reading and data-sending tools — potential exfiltration vector",
        evidence: `Read: [${readTools.join(", ")}] → Send: [${sendTools.join(", ")}]`,
        fix: "Separate read and send capabilities into different servers, or add output filtering",
      });

      if (encodeTools.length > 0) {
        findings.push({
          ruleId: `EXFIL-${String(counter++).padStart(3, "0")}`,
          ruleName: "Encoding-assisted exfiltration",
          severity: "CRITICAL",
          message: "Exfiltration chain includes encoding tools — data can be obfuscated before sending",
          evidence: `Read: [${readTools.join(", ")}] → Encode: [${encodeTools.join(", ")}] → Send: [${sendTools.join(", ")}]`,
          fix: "Remove encoding tools or separate them from the read/send chain",
        });
      }
    }

    for (const tool of target.tools) {
      const desc = (tool.description ?? "").toLowerCase();
      const hasReadInDesc = /\bread\b.*\bfile\b|\bfetch\b.*\bdata\b|\baccess\b.*\bdatabase\b/i.test(desc);
      const hasSendInDesc = /\bsend\b|\bpost\b|\bupload\b|\btransmit\b|\bforward\b/i.test(desc);

      if (hasReadInDesc && hasSendInDesc) {
        findings.push({
          ruleId: `EXFIL-${String(counter++).padStart(3, "0")}`,
          ruleName: "Single-tool exfiltration risk",
          severity: "HIGH",
          toolName: tool.name,
          message: `Tool "${tool.name}" can both read data and send it externally`,
          evidence: tool.description?.slice(0, 200) ?? "",
          fix: "Split into separate read and write tools with explicit user confirmation",
        });
      }
    }

    return findings;
  },
};

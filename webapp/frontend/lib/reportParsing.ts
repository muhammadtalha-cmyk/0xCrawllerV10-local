export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];

export interface Finding {
  severity: Severity;
  rawSeverity: string;
  template: string;
  host: string;
  matchedAt: string;
  cve: string;
  raw: Record<string, unknown>;
}

export function normalizeSeverity(value: unknown): Severity {
  const text = String(value ?? "").trim().toLowerCase();
  if (text === "critical") return "critical";
  if (text === "high") return "high";
  if (text === "medium" || text === "moderate") return "medium";
  if (text === "low") return "low";
  if (text === "info" || text === "informational") return "info";
  return "unknown";
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (Array.isArray(value) && value.length) return String(value[0]);
    if (typeof value === "string" && value) return value;
    if (typeof value === "number") return String(value);
  }
  return "";
}

/**
 * Nuclei-style findings usually look like:
 *   { "info": { "severity": "high", "name": "..." }, "template-id": "...", "host": "...", "matched-at": "..." }
 * but pipelines vary, so this reads from either the top level or a nested "info" object.
 */
function toFinding(entry: Record<string, unknown>): Finding {
  const info = (entry.info && typeof entry.info === "object" ? entry.info : {}) as Record<string, unknown>;
  const rawSeverity = firstString(entry.severity, info.severity, entry.risk, entry.Severity) || "unknown";
  return {
    severity: normalizeSeverity(rawSeverity),
    rawSeverity,
    template: firstString(entry.template_name, entry["template-id"], entry.template_id, info.name, entry.name, entry.check, "Unnamed finding"),
    host: firstString(entry.host, entry.url, entry.matched_at, entry["matched-at"], entry.target, entry.ip, "—"),
    matchedAt: firstString(entry["matched-at"], entry.matched_at, entry.url, entry.host, "—"),
    cve: firstString(entry.cve, info.cve, entry.cve_id, entry.cveId) || "—",
    raw: entry,
  };
}

/** Returns true if a parsed object looks like a single nuclei/vuln finding. */
function looksLikeFinding(entry: unknown): entry is Record<string, unknown> {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const record = entry as Record<string, unknown>;
  const info = (record.info && typeof record.info === "object" ? record.info : {}) as Record<string, unknown>;
  return "severity" in record || "severity" in info || "template-id" in record || "template_id" in record || "risk" in record;
}

/**
 * Walks a parsed JSON payload looking for an array of finding-shaped objects.
 * Handles: a bare array, or an object wrapping the array under a common key
 * such as "findings" / "results" / "vulnerabilities" / "issues".
 */
export function extractFindings(payload: unknown): Finding[] | null {
  const candidateArrays: unknown[][] = [];
  if (Array.isArray(payload)) candidateArrays.push(payload);
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    for (const key of ["findings", "results", "vulnerabilities", "issues", "matches", "items", "data"]) {
      const value = (payload as Record<string, unknown>)[key];
      if (Array.isArray(value)) candidateArrays.push(value);
    }
  }
  for (const array of candidateArrays) {
    if (array.length && array.every(looksLikeFinding)) {
      return array.map((entry) => toFinding(entry as Record<string, unknown>));
    }
  }
  return null;
}

export function computeSeverityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Generic best-effort scan of an arbitrary JSON payload for a numeric stat
 * (e.g. "how many subdomains"). Looks for keys matching the given keywords
 * whose value is a number, or an array under a matching key (array length).
 * Pipelines differ in field naming, so this is intentionally permissive —
 * treat the result as an estimate and double check against the source file.
 */
export function findNumericStat(payload: unknown, keywords: string[], depth = 0): number | null {
  if (depth > 4 || payload === null || payload === undefined) return null;
  if (Array.isArray(payload)) {
    for (const item of payload) {
      const found = findNumericStat(item, keywords, depth + 1);
      if (found !== null) return found;
    }
    return null;
  }
  if (typeof payload === "object") {
    const entries = Object.entries(payload as Record<string, unknown>);
    for (const [key, value] of entries) {
      const lowerKey = key.toLowerCase();
      if (keywords.some((word) => lowerKey.includes(word))) {
        if (typeof value === "number") return value;
        if (Array.isArray(value)) return value.length;
      }
    }
    for (const [, value] of entries) {
      const found = findNumericStat(value, keywords, depth + 1);
      if (found !== null) return found;
    }
  }
  return null;
}

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
}

/** Minimal RFC4180-ish CSV parser: handles quoted fields and escaped quotes, no external dependency. */
export function parseCsv(text: string): ParsedCsv {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (inQuotes) {
      if (char === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 1; } else { inQuotes = false; }
      } else field += char;
      continue;
    }
    if (char === '"') { inQuotes = true; continue; }
    if (char === ",") { row.push(field); field = ""; continue; }
    if (char === "\n" || char === "\r") {
      if (char === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field);
      field = "";
      if (row.some((cell) => cell.length)) rows.push(row);
      row = [];
      continue;
    }
    field += char;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }

  const [headers, ...body] = rows;
  return { headers: headers || [], rows: body };
}

/** Maps a filename to a react-syntax-highlighter language for code blocks. */
export function languageForName(name: string): string {
  const lower = name.toLowerCase();
  if (lower.endsWith(".json") || lower.endsWith(".jsonl")) return "json";
  if (lower.endsWith(".csv")) return "csv";
  if (lower.endsWith(".md") || lower.endsWith(".mmd")) return "markdown";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  if (lower.endsWith(".log") || lower.endsWith(".txt")) return "log";
  return "text";
}
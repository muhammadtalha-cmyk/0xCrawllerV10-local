import type { Severity } from "@/lib/reportParsing";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity}`}>{severity}</span>;
}
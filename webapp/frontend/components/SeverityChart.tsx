import type { Severity } from "@/lib/reportParsing";

export function SeverityChart({ counts }: { counts: Record<Severity, number> }) {
  const entries = [
    ["critical", counts.critical],
    ["high", counts.high],
    ["medium", counts.medium],
    ["low", counts.low],
    ["info", counts.info],
  ] as const;
  const total = entries.reduce((sum, [, value]) => sum + value, 0);
  let cursor = 0;
  const gradient = total ? `conic-gradient(${entries.map(([severity, value]) => { const start = cursor; cursor += (value / total) * 100; return `var(--severity-${severity}) ${start}% ${cursor}%`; }).join(",")})` : "conic-gradient(var(--panel-border) 0 100%)";
  return <div className="severity-chart-native"><div className="native-donut" style={{ background: gradient }}><span><strong>{total}</strong><small>findings</small></span></div><div className="native-chart-legend">{entries.map(([severity, value]) => <div key={severity}><i className={`severity-dot ${severity}`} /><span>{severity}</span><strong>{value}</strong></div>)}</div></div>;
}

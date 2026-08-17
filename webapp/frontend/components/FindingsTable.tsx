"use client";

import { type ChangeEvent, useMemo, useState } from "react";
import { SEVERITY_ORDER, type Finding, type Severity } from "@/lib/reportParsing";
import { SeverityBadge } from "./SeverityBadge";
import { SearchIcon, SortIcon } from "./Icons";

type SortKey = "severity" | "template" | "host" | "cve";

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set(SEVERITY_ORDER));
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const present = useMemo(() => SEVERITY_ORDER.filter((severity) => findings.some((f) => f.severity === severity)), [findings]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return findings.filter((finding) => {
      if (!activeSeverities.has(finding.severity)) return false;
      if (!query) return true;
      return (
        finding.template.toLowerCase().includes(query) ||
        finding.host.toLowerCase().includes(query) ||
        finding.cve.toLowerCase().includes(query)
      );
    });
  }, [findings, activeSeverities, search]);

  const sorted = useMemo(() => {
    const severityRank = (severity: Severity) => SEVERITY_ORDER.indexOf(severity);
    const compare = (a: Finding, b: Finding) => {
      if (sortKey === "severity") return severityRank(a.severity) - severityRank(b.severity);
      return a[sortKey].localeCompare(b[sortKey]);
    };
    const rows = [...filtered].sort(compare);
    return sortDir === "asc" ? rows : rows.reverse();
  }, [filtered, sortKey, sortDir]);

  function toggleSeverity(severity: Severity) {
    setActiveSeverities((current) => {
      const next = new Set(current);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next.size ? next : new Set(SEVERITY_ORDER);
    });
  }

  function sortBy(key: SortKey) {
    if (key === sortKey) setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("asc"); }
  }

  if (!findings.length) {
    return <div className="empty-state"><h3>No vulnerability findings indexed</h3><p>Nuclei results will populate this table once the technology stage finishes.</p></div>;
  }

  return (
    <div className="findings-table-wrap">
      <div className="findings-toolbar">
        <div className="findings-filters">
          {present.map((severity) => (
            <button
              key={severity}
              className={`severity-filter severity-${severity} ${activeSeverities.has(severity) ? "active" : ""}`}
              onClick={() => toggleSeverity(severity)}
            >
              {severity} · {findings.filter((f) => f.severity === severity).length}
            </button>
          ))}
        </div>
        <div className="findings-search">
          <SearchIcon />
          <input placeholder="Filter by host, template, or CVE" value={search} onChange={(event: ChangeEvent<HTMLInputElement>) => setSearch(event.target.value)} />
        </div>
      </div>

      <div className="findings-table-scroll">
        <table className="findings-table">
          <thead>
            <tr>
              {([
                ["severity", "Severity"],
                ["template", "Template"],
                ["host", "Host"],
                ["cve", "CVE"],
              ] as const).map(([key, label]) => (
                <th key={key} onClick={() => sortBy(key)}>
                  {label} <SortIcon className={sortKey === key ? `active ${sortDir}` : ""} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((finding, index) => (
              <tr key={`${finding.template}-${finding.host}-${index}`}>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td className="findings-template">{finding.template}</td>
                <td className="findings-host">{finding.host}</td>
                <td>{finding.cve}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="findings-count">{sorted.length} of {findings.length} findings shown</div>
    </div>
  );
}
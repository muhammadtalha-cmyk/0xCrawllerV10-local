import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { IntelligenceData } from "@/lib/securityIntelligence";
import { FingerprintIcon, SearchIcon, ShieldAlertIcon } from "../Icons";
import { TechnologyLogo } from "./TechnologyLogo";

export interface TechnologyIntel {
  name: string;
  category: string;
  version: string | null;
  confidence: string;
  confidenceScore: number | null;
  sources: string[];
  host: string;
  hosts: string[];
  hostCount: number;
  risk: "critical" | "high" | "medium" | "low" | "unrated";
  serviceConfirmed: boolean;
}

function versionLabel(technology: TechnologyIntel): string {
  return technology.version || "Version not exposed";
}

function confidenceLabel(technology: TechnologyIntel): string {
  if (technology.confidenceScore !== null) {
    return `${Math.round(technology.confidenceScore * 100)}%`;
  }
  return technology.confidence || "Unknown";
}

function toneForTechnology(technology: TechnologyIntel): string {
  if (technology.risk === "critical" || technology.risk === "high") return "danger";
  if (technology.risk === "medium") return "amber";
  if (technology.confidenceScore !== null && technology.confidenceScore >= 0.85) return "cyan";
  return "blue";
}

function TechnologyCard({ technology }: { technology: TechnologyIntel }) {
  const hostDisplay =
    technology.hostCount > 1
      ? `${technology.hostCount} hosts`
      : technology.host || "Target asset";

  return (
    <article className={`technology-card tone-${toneForTechnology(technology)}`}>
      <div className="technology-card-head">
        <span className="technology-logo">
          <TechnologyLogo name={technology.name} />
        </span>
        <div>
          <h3>{technology.name}</h3>
          <small>{technology.category}</small>
        </div>
      </div>
      <dl>
        <div>
          <dt>Version</dt>
          <dd>{versionLabel(technology)}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{confidenceLabel(technology)}</dd>
        </div>
        <div>
          <dt>Detection</dt>
          <dd>{technology.sources.join(", ") || "Fingerprint"}</dd>
        </div>
        <div>
          <dt>Scope</dt>
          <dd title={technology.hosts.join(", ")}>{hostDisplay}</dd>
        </div>
      </dl>
      <footer>
        <span className={`risk-chip ${technology.risk}`}>
          Risk: {technology.risk === "unrated" ? "Not rated" : technology.risk}
        </span>
        {technology.serviceConfirmed && (
          <span className="service-confirmed">Service confirmed</span>
        )}
      </footer>
    </article>
  );
}

const CATEGORY_LAYER: Array<{ key: string; label: string; matcher: RegExp }> = [
  { key: "edge", label: "CDN / WAF", matcher: /cdn|security edge|waf|cloudflare|front door|akamai|fastly/i },
  { key: "server", label: "Web server", matcher: /web server|server|proxy|nginx|apache|iis|caddy/i },
  { key: "frontend", label: "Frontend", matcher: /frontend|javascript|ui framework|cms|wordpress|react|angular|vue|next|sweetalert|mathjax|jquery|tailwind/i },
  { key: "backend", label: "Backend", matcher: /backend|runtime|programming language|php|python|node|java|ruby|golang|c#|\.net/i },
  { key: "database", label: "Database", matcher: /database|cache|queue|search|redis|postgres|mysql|mongodb|elasticsearch/i },
];

function TechnologyStack({ technologies }: { technologies: TechnologyIntel[] }) {
  const layers = CATEGORY_LAYER.map((layer) => ({
    ...layer,
    items: technologies.filter((t) => layer.matcher.test(`${t.category} ${t.name}`)),
  })).filter((layer) => layer.items.length);

  return (
    <section className="intel-panel technology-stack-panel" style={{ marginTop: "16px" }}>
      <header className="panel-heading">
        <div>
          <small>Architecture inference</small>
          <h3>Technology stack</h3>
        </div>
        <FingerprintIcon />
      </header>
      <div className="stack-diagram">
        <div className="stack-user-node">User / Client</div>
        {layers.map((layer, index) => (
          <div className="stack-layer-wrap" key={layer.key}>
            <span className="stack-connector" />
            <div className={`stack-layer layer-${layer.key}`}>
              <small>{layer.label}</small>
              <div>
                {layer.items.slice(0, 5).map((tech) => (
                  <span key={`${layer.key}-${tech.name}`}>
                    <TechnologyLogo name={tech.name} />
                    {tech.name}
                    {tech.version ? ` ${tech.version}` : ""}
                  </span>
                ))}
              </div>
            </div>
            {index === layers.length - 1 && <span className="stack-terminal" />}
          </div>
        ))}
        {!layers.length && (
          <p className="coverage-note">No technology categories were available to assemble a stack.</p>
        )}
      </div>
      <p className="provider-footnote">
        This diagram groups observed fingerprints by category. It does not claim unobserved architectural relationships.
      </p>
    </section>
  );
}

function SeverityBars({ data }: { data: IntelligenceData }) {
  const entries = [
    ["Critical", data.severityCounts.critical || 0, "critical"],
    ["High", data.severityCounts.high || 0, "high"],
    ["Medium", data.severityCounts.medium || 0, "medium"],
    ["Low", data.severityCounts.low || 0, "low"],
  ] as const;
  const max = Math.max(1, ...entries.map(([, value]) => value));

  return (
    <section className="intel-panel severity-bars-panel">
      <header className="panel-heading">
        <div>
          <small>Vulnerability intelligence</small>
          <h3>Severity distribution</h3>
        </div>
      </header>
      <div className="severity-bars">
        {entries.map(([label, value, tone]) => (
          <div key={label}>
            <span>{label}</span>
            <i>
              <b className={tone} style={{ height: `${value ? Math.max(12, (value / max) * 100) : 3}%` }} />
            </i>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

function RiskHeatmap({ data }: { data: IntelligenceData }) {
  const rows = [
    ["Critical", data.severityCounts.critical || 0],
    ["High", data.severityCounts.high || 0],
    ["Medium", data.severityCounts.medium || 0],
    ["Low", data.severityCounts.low || 0],
  ] as const;
  const activity = [
    data.metrics.subdomains || 0,
    data.metrics.liveAssets || 0,
    data.metrics.endpoints || 0,
    data.metrics.screenshots || 0,
  ];
  const maxActivity = Math.max(1, ...activity);

  return (
    <section className="intel-panel risk-heatmap-panel">
      <header className="panel-heading">
        <div>
          <small>Evidence matrix</small>
          <h3>Recon and risk heatmap</h3>
        </div>
        <span>Real scan counts</span>
      </header>
      <div className="heatmap-labels">
        <span>DNS</span>
        <span>HTTP</span>
        <span>Endpoints</span>
        <span>Screenshots</span>
      </div>
      <div className="heatmap-grid">
        {rows.map(([label, severityValue], rowIndex) => (
          <div className="heatmap-row" key={label}>
            <strong>{label}</strong>
            {activity.map((value, columnIndex) => {
              const activityOpacity = maxActivity > 0 ? value / maxActivity : 0;
              const riskBoost = severityValue ? Math.min(1, severityValue / 5) : 0;
              const opacity = Math.max(0.08, Math.min(0.95, activityOpacity * 0.6 + riskBoost * 0.4));
              return <i key={`${rowIndex}-${columnIndex}`} style={{ opacity }} />;
            })}
          </div>
        ))}
      </div>
      <p className="provider-footnote">
        Color intensity combines observed activity volume with indexed severity counts.
      </p>
    </section>
  );
}

function FindingSummary({ findings }: { findings: any[] }) {
  const top = [...findings]
    .sort((a, b) => {
      const ranks: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
      return (ranks[b.severity?.toLowerCase()] || 0) - (ranks[a.severity?.toLowerCase()] || 0);
    })
    .slice(0, 4);

  return (
    <section className="intel-panel finding-summary-panel">
      <header className="panel-heading">
        <div>
          <small>Priority queue</small>
          <h3>Critical findings summary</h3>
        </div>
        <ShieldAlertIcon />
      </header>
      {top.length ? (
        <div className="finding-summary-list">
          {top.map((finding, index) => (
            <article key={`${finding.finding_type || finding.id}-${index}`}>
              <span className={`severity-dot ${finding.severity?.toLowerCase() || "info"}`} />
              <div>
                <strong>{finding.finding_type || finding.description?.slice(0, 30) || "Finding"}</strong>
                <small>{finding.hostname || "Target asset"}</small>
              </div>
              <b>{finding.severity?.toUpperCase() || "INFO"}</b>
            </article>
          ))}
        </div>
      ) : (
        <p className="coverage-note">No indexed findings are available for prioritization.</p>
      )}
    </section>
  );
}

const IGNORED_NOISE = new Set([
  "ip",
  "script",
  "title",
  "html5",
  "country",
  "uncommonheaders",
  "strict-transport-security",
  "email",
  "x-frame-options",
  "x-xss-protection",
  "content-security-policy",
  "http-server",
  "cookies",
]);

export function TechnologyView({ data }: { data: IntelligenceData }) {
  const [technologies, setTechnologies] = useState<TechnologyIntel[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [selectedLayer, setSelectedLayer] = useState<string>("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    Promise.all([
      api.getTechnologies(data.scanId, 500, 0).catch(() => ({ items: [], total: 0 })),
      api.getFindings(data.scanId, 20, 0).catch(() => ({ items: [], total: 0 })),
    ]).then(([techRes, findRes]) => {
      if (cancelled) return;

      const rawItems = techRes.items || [];
      const grouped = new Map<string, TechnologyIntel>();

      for (const item of rawItems) {
        const rawName = (item.name || "").trim();
        if (!rawName) continue;

        // Filter out generic HTTP headers / noise if they don't have an exact software version
        if (!item.version && IGNORED_NOISE.has(rawName.toLowerCase())) {
          continue;
        }

        const normVersion = item.version?.trim() || null;
        const key = `${rawName.toLowerCase()}|${normVersion || ""}`;
        const host = item.hostname || item.evidence?.host || "Host";

        const existing = grouped.get(key);
        if (existing) {
          if (!existing.hosts.includes(host)) {
            existing.hosts.push(host);
            existing.hostCount += 1;
          }
          if (item.detection_source && !existing.sources.includes(item.detection_source)) {
            existing.sources.push(item.detection_source);
          }
          if (item.evidence?.service_confirmed) {
            existing.serviceConfirmed = true;
          }
        } else {
          const evidence = item.evidence || {};
          const confScore =
            evidence.confidence_score ??
            (item.confidence === "certain"
              ? 0.95
              : item.confidence === "high"
              ? 0.85
              : 0.7);
          const risk = evidence.risk || (normVersion ? "medium" : "unrated");
          const sources =
            evidence.sources || (item.detection_source ? [item.detection_source] : ["whatweb"]);

          grouped.set(key, {
            name: rawName,
            category: item.category || evidence.category || "Technology",
            version: normVersion,
            confidence: item.confidence || "medium",
            confidenceScore: confScore,
            sources,
            host,
            hosts: [host],
            hostCount: 1,
            risk,
            serviceConfirmed: Boolean(evidence.service_confirmed),
          });
        }
      }

      const list = [...grouped.values()].sort((a, b) => {
        if (a.version && !b.version) return -1;
        if (!a.version && b.version) return 1;
        return b.hostCount - a.hostCount;
      });

      setTechnologies(list);
      setFindings(findRes.items || []);
      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [data.scanId]);

  // Filtering
  const filtered = technologies.filter((tech) => {
    const matchesSearch = query
      ? `${tech.name} ${tech.category} ${tech.version || ""} ${tech.hosts.join(" ")}`
          .toLowerCase()
          .includes(query.toLowerCase())
      : true;

    if (!matchesSearch) return false;

    if (selectedLayer === "all") return true;
    const matcher = CATEGORY_LAYER.find((l) => l.key === selectedLayer)?.matcher;
    return matcher ? matcher.test(`${tech.category} ${tech.name}`) : true;
  });

  return (
    <div className="technology-view">
      <div
        className="intel-title-row"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "14px",
        }}
      >
        <div>
          <small>Evidence-backed fingerprints</small>
          <h2>Technology Intelligence</h2>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <div
            className="search-bar"
            style={{
              display: "flex",
              alignItems: "center",
              background: "rgba(255,255,255,0.04)",
              border: "1px solid var(--panel-border)",
              borderRadius: "8px",
              padding: "4px 10px",
              gap: "6px",
            }}
          >
            <SearchIcon style={{ width: "14px", height: "14px", color: "var(--muted)" }} />
            <input
              type="text"
              placeholder="Search tech, version, host..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{
                background: "transparent",
                border: "none",
                color: "inherit",
                fontSize: "12px",
                outline: "none",
                width: "180px",
              }}
            />
            {query && (
              <button
                onClick={() => setQuery("")}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  cursor: "pointer",
                  fontSize: "12px",
                }}
              >
                ✕
              </button>
            )}
          </div>
          <span className="intelligence-badge">
            <FingerprintIcon /> {technologies.length} unique components
          </span>
        </div>
      </div>

      {/* Layer Filter Chips */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "14px", flexWrap: "wrap" }}>
        <button
          className={`btn ${selectedLayer === "all" ? "primary" : "secondary"}`}
          onClick={() => setSelectedLayer("all")}
          style={{ padding: "4px 10px", fontSize: "11px" }}
        >
          All ({technologies.length})
        </button>
        {CATEGORY_LAYER.map((layer) => {
          const count = technologies.filter((t) =>
            layer.matcher.test(`${t.category} ${t.name}`)
          ).length;
          if (!count) return null;
          return (
            <button
              key={layer.key}
              className={`btn ${selectedLayer === layer.key ? "primary" : "secondary"}`}
              onClick={() => setSelectedLayer(selectedLayer === layer.key ? "all" : layer.key)}
              style={{
                padding: "4px 10px",
                fontSize: "11px",
              }}
            >
              {layer.label} ({count})
            </button>
          );
        })}
      </div>

      {loading ? (
        <div
          className="intelligence-loading"
          style={{ padding: "40px", textAlign: "center", color: "var(--muted)" }}
        >
          <FingerprintIcon
            style={{ width: "32px", height: "32px", opacity: 0.5, margin: "auto" }}
          />
          <p style={{ marginTop: "8px" }}>Loading technology fingerprints from database...</p>
        </div>
      ) : (
        <>
          <div className="technology-layout">
            <div className="technology-grid">
              {filtered.length ? (
                filtered.map((tech) => (
                  <TechnologyCard
                    key={`${tech.name}-${tech.version || "none"}`}
                    technology={tech}
                  />
                ))
              ) : (
                <div
                  className="empty-compact"
                  style={{ gridColumn: "1 / -1", padding: "40px", textAlign: "center" }}
                >
                  <FingerprintIcon />
                  <span>No technologies match your search or filter.</span>
                </div>
              )}
            </div>

            <aside className="technology-side">
              <RiskHeatmap data={data} />
              <SeverityBars data={data} />
              <FindingSummary findings={findings} />
            </aside>
          </div>

          <TechnologyStack technologies={technologies} />
        </>
      )}
    </div>
  );
}

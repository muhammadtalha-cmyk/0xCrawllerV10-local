import type { ReactNode } from "react";
import type { Severity } from "@/lib/reportParsing";
import { SeverityChart } from "./SeverityChart";
import { DatabaseIcon, GlobeIcon, LayersIcon, RadarIcon } from "./Icons";

export interface DashboardStats {
  subdomains: number | null;
  liveHosts: number | null;
  technologies: number | null;
  severityCounts: Record<Severity, number>;
}

export function StatsDashboard({ stats }: { stats: DashboardStats }) {
  const totalFindings = Object.values(stats.severityCounts).reduce((sum, value) => sum + value, 0);

  return (
    <section className="stats-dashboard">
      <div className="stat-cards">
        <StatCard icon={<GlobeIcon />} label="Subdomains found" value={stats.subdomains} accent="blue" />
        <StatCard icon={<RadarIcon />} label="Live hosts" value={stats.liveHosts} accent="green" />
        <StatCard icon={<LayersIcon />} label="Technologies detected" value={stats.technologies} accent="amber" />
        <StatCard icon={<DatabaseIcon />} label="Findings" value={totalFindings} accent="red" />
      </div>

      {totalFindings > 0 && (
        <div className="severity-summary">
          <div className="severity-summary-cards">
            {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => (
              <div key={severity} className={`severity-card severity-${severity}`}>
                <strong>{stats.severityCounts[severity]}</strong>
                <span>{severity}</span>
              </div>
            ))}
          </div>
          <div className="chart-card">
            <SeverityChart counts={stats.severityCounts} />
          </div>
        </div>
      )}
    </section>
  );
}

function StatCard({ icon, label, value, accent }: { icon: ReactNode; label: string; value: number | null; accent: "blue" | "green" | "amber" | "red" }) {
  return (
    <div className={`stat-card accent-${accent}`}>
      <span className="stat-card-icon">{icon}</span>
      <div>
        <strong>{value === null ? "—" : value.toLocaleString()}</strong>
        <small>{label}</small>
      </div>
    </div>
  );
}
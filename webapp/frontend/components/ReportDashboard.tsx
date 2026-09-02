"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { loadSecurityIntelligence, type IntelligenceData } from "@/lib/securityIntelligence";
import type { Artifact, Scan } from "@/lib/types";
import {
  DatabaseIcon,
  FileIcon,
  FingerprintIcon,
  ImageIcon,
  RadarIcon,
  ShieldAlertIcon,
} from "./Icons";
import { SecurityOverview } from "./intelligence/SecurityOverview";
import { AttackSurfaceView } from "./intelligence/AttackSurfaceView";
import { TechnologyView } from "./intelligence/TechnologyView";
import { VulnerabilityView } from "./intelligence/VulnerabilityView";
import { ScreenshotView } from "./intelligence/ScreenshotView";
import { TechnicalEvidenceView } from "./intelligence/TechnicalEvidenceView";

type IntelligenceTab = "overview" | "attack-surface" | "technology" | "vulnerabilities" | "screenshots" | "technical";

export function ReportDashboard({ scan, artifacts, onOpenArtifact }: { scan: Scan; artifacts: Artifact[]; onOpenArtifact: (artifact: Artifact) => void }) {
  const [tab, setTab] = useState<IntelligenceTab>("overview");
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [error, setError] = useState("");

  const artifactSignature = useMemo(
    () => artifacts.map((artifact) => `${artifact.id}:${artifact.size_bytes}`).sort().join("|"),
    [artifacts]
  );

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError("");
    loadSecurityIntelligence(artifacts, scan)
      .then((next) => { if (!cancelled) setData(next); })
      .catch((reason: unknown) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "Unable to build security intelligence view"); });
    return () => { cancelled = true; };
    // artifactSignature is a stable representation of the indexed artifact set.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [artifactSignature, scan.id, scan.status, scan.completed_at]);

  const screenshots = useMemo(() => artifacts.filter((artifact) => artifact.kind === "screenshot" || artifact.kind === "image"), [artifacts]);
  const tabs: Array<{ key: IntelligenceTab; label: string; icon: ReactNode; count?: number }> = [
    { key: "overview", label: "Security overview", icon: <RadarIcon /> },
    { key: "attack-surface", label: "Attack surface", icon: <DatabaseIcon />, count: data?.metrics.totalAssets ?? undefined },
    { key: "technology", label: "Technology", icon: <FingerprintIcon />, count: data?.metrics.technologies ?? undefined },
    { key: "vulnerabilities", label: "Vulnerabilities", icon: <ShieldAlertIcon />, count: (data?.severityCounts.critical || 0) + (data?.severityCounts.high || 0) + (data?.severityCounts.medium || 0) + (data?.severityCounts.low || 0) + (data?.severityCounts.info || 0) },
    { key: "screenshots", label: "Screenshots", icon: <ImageIcon />, count: screenshots.length },
    { key: "technical", label: "Technical report", icon: <FileIcon /> },
  ];

  if (error) return <div className="error-banner">{error}</div>;
  if (!data) return <div className="intelligence-loading"><div className="loader" /><div><strong>Building security intelligence</strong><span>Reading normalized assets, technologies, findings, and evidence artifacts…</span></div></div>;

  return (
    <div className="intelligence-workspace">
      <nav className="intelligence-nav" aria-label="Security intelligence sections">
        {tabs.map((item) => (
          <button key={item.key} className={tab === item.key ? "active" : ""} onClick={() => setTab(item.key)}>
            {item.icon}<span>{item.label}</span>{item.count !== undefined && <b>{item.count}</b>}
          </button>
        ))}
      </nav>

      <div className="intelligence-content">
        {tab === "overview" && <SecurityOverview data={data} scan={scan} />}
        {tab === "attack-surface" && <AttackSurfaceView data={data} scan={scan} onOpenArtifact={onOpenArtifact} />}
        {tab === "technology" && <TechnologyView data={data} />}
        {tab === "vulnerabilities" && <VulnerabilityView data={data} />}
        {tab === "screenshots" && <ScreenshotView screenshots={screenshots} data={data} onOpenArtifact={onOpenArtifact} />}
        {tab === "technical" && <TechnicalEvidenceView scan={scan} reportArtifact={data.combinedReportArtifact} artifacts={artifacts} onOpenArtifact={onOpenArtifact} />}
      </div>
    </div>
  );
}

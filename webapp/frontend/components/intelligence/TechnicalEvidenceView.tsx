"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Artifact } from "@/lib/types";
import { ArtifactList } from "../ArtifactList";
import { FileIcon, ShieldAlertIcon } from "../Icons";
import { MarkdownReport } from "../MarkdownReport";

export function TechnicalEvidenceView({ reportArtifact, artifacts, onOpenArtifact }: { reportArtifact: Artifact | null; artifacts: Artifact[]; onOpenArtifact: (artifact: Artifact) => void }) {
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [error, setError] = useState("");
  const reports = artifacts.filter((artifact) => artifact.kind === "report");
  const evidence = artifacts.filter((artifact) => artifact.kind === "data" || artifact.kind === "log");

  useEffect(() => {
    let cancelled = false;
    setReportMarkdown(null);
    setError("");
    if (!reportArtifact) return;
    api.artifactText(reportArtifact.id)
      .then((text) => { if (!cancelled) setReportMarkdown(text); })
      .catch((reason: unknown) => { if (!cancelled) setError(reason instanceof Error ? reason.message : "Unable to load technical report"); });
    return () => { cancelled = true; };
  }, [reportArtifact]);

  return (
    <div className="technical-evidence-view">
      <div className="intel-title-row"><div><small>Forensic record</small><h2>Technical Evidence Report</h2></div><span className="intelligence-badge"><FileIcon /> {artifacts.length} artifacts</span></div>
      <div className="technical-warning"><ShieldAlertIcon /><div><strong>Detailed technical evidence</strong><span>This view intentionally preserves full scanner output, tables, source reports, and raw artifacts. It is loaded only after opening this tab.</span></div></div>
      {error && <div className="error-banner">{error}</div>}
      {reportArtifact && reportMarkdown === null && !error && <div className="intelligence-loading"><div className="loader" /><div><strong>Loading technical report</strong><span>Opening the V10 combined evidence document…</span></div></div>}
      {reportMarkdown ? <section className="technical-report-document"><MarkdownReport markdown={reportMarkdown} /></section> : !reportArtifact && <div className="empty-state"><FileIcon /><h3>Combined report not indexed</h3><p>The V10 report will appear after the final pipeline stage.</p></div>}
      <ArtifactList title="Stage reports" items={reports} empty="No report artifacts are available." onOpen={onOpenArtifact} />
      <ArtifactList title="Supporting evidence" items={evidence} empty="No supporting evidence is indexed." onOpen={onOpenArtifact} />
    </div>
  );
}

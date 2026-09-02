"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Artifact, Scan } from "@/lib/types";
import { formatBytes } from "@/lib/format";
import { ArtifactList } from "../ArtifactList";
import { DownloadIcon, FileIcon, ShieldAlertIcon } from "../Icons";
import { MarkdownReport } from "../MarkdownReport";

const MAX_AUTO_PREVIEW_BYTES = 1024 * 1024; // 1 MB preview for combined report

export function TechnicalEvidenceView({
  scan,
  reportArtifact,
  artifacts,
  onOpenArtifact,
}: {
  scan: Scan;
  reportArtifact: Artifact | null;
  artifacts: Artifact[];
  onOpenArtifact: (artifact: Artifact) => void;
}) {
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [isTruncated, setIsTruncated] = useState(false);
  const [loadingFull, setLoadingFull] = useState(false);
  const [error, setError] = useState("");
  const reports = artifacts.filter((artifact) => artifact.kind === "report");
  const evidence = artifacts.filter((artifact) => artifact.kind === "data" || artifact.kind === "log");

  const effectiveReport = reportArtifact || reports[0] || null;
  const isLarge = Boolean(effectiveReport && (effectiveReport.size_bytes || 0) > MAX_AUTO_PREVIEW_BYTES);

  useEffect(() => {
    let cancelled = false;
    setReportMarkdown(null);
    setIsTruncated(false);
    setLoadingFull(false);
    setError("");

    const loadReport = async () => {
      try {
        let text: string | null = null;
        try {
          const sections = await api.getReportSections(scan.id, "combined");
          if (sections && Array.isArray(sections) && sections.length > 0) {
            const sorted = [...sections].sort((a: any, b: any) => {
              const idxA = a.section_index ?? a.section_order ?? 0;
              const idxB = b.section_index ?? b.section_order ?? 0;
              return idxA - idxB;
            });
            text = sorted.map((s: any) => s.content).join("\n\n");
          }
        } catch {
          // Ignore sections error and fallback
        }

        if (!text && effectiveReport) {
          const fetchLimit = isLarge ? MAX_AUTO_PREVIEW_BYTES : undefined;
          text = await api.artifactText(effectiveReport.id, fetchLimit);
          if (isLarge) setIsTruncated(true);
        }

        if (!cancelled) {
          setReportMarkdown(text || null);
        }
      } catch (reason: unknown) {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : "Unable to load technical report");
        }
      }
    };

    loadReport();

    return () => {
      cancelled = true;
    };
  }, [scan.id, effectiveReport?.id, isLarge]);

  const handleLoadFull = async () => {
    if (!effectiveReport) return;
    setLoadingFull(true);
    try {
      const fullText = await api.artifactText(effectiveReport.id);
      setReportMarkdown(fullText);
      setIsTruncated(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load full report");
    } finally {
      setLoadingFull(false);
    }
  };

  return (
    <div className="technical-evidence-view">
      <div className="intel-title-row">
        <div>
          <small>Forensic record</small>
          <h2>Technical Evidence Report</h2>
        </div>
        <span className="intelligence-badge">
          <FileIcon /> {artifacts.length} artifacts
        </span>
      </div>
      <div className="technical-warning">
        <ShieldAlertIcon />
        <div>
          <strong>Detailed technical evidence</strong>
          <span>This view intentionally preserves full scanner output, tables, source reports, and raw artifacts.</span>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}

      {effectiveReport && isTruncated && (
        <div
          className="preview-banner"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "12px 16px",
            background: "rgba(255, 255, 255, 0.05)",
            borderRadius: "8px",
            marginBottom: "16px",
            border: "1px solid rgba(255, 255, 255, 0.1)",
          }}
        >
          <span style={{ fontSize: "13px" }}>
            Showing initial preview ({formatBytes(MAX_AUTO_PREVIEW_BYTES)} of {formatBytes(effectiveReport.size_bytes)}).
          </span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="btn secondary"
              onClick={handleLoadFull}
              disabled={loadingFull}
              style={{ padding: "6px 12px", fontSize: "13px" }}
            >
              {loadingFull ? "Loading full..." : "Load full in browser"}
            </button>
            <a
              className="btn primary"
              href={api.artifactUrl(effectiveReport.id, true)}
              download
              style={{
                padding: "6px 12px",
                fontSize: "13px",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
              }}
            >
              <DownloadIcon /> Download full file
            </a>
          </div>
        </div>
      )}

      {effectiveReport && reportMarkdown === null && !error && (
        <div className="intelligence-loading">
          <div className="loader" />
          <div>
            <strong>Loading technical report</strong>
            <span>Opening evidence document…</span>
          </div>
        </div>
      )}
      {reportMarkdown ? (
        <section className="technical-report-document">
          <MarkdownReport markdown={reportMarkdown} />
        </section>
      ) : (
        !effectiveReport && (
          <div className="empty-state">
            <FileIcon />
            <h3>Combined report not indexed</h3>
            <p>The report will appear after the pipeline stages complete.</p>
          </div>
        )
      )}
      <ArtifactList title="Stage reports" items={reports} empty="No report artifacts are available." onOpen={onOpenArtifact} />
      <ArtifactList title="Supporting evidence" items={evidence} empty="No supporting evidence is indexed." onOpen={onOpenArtifact} />
    </div>
  );
}

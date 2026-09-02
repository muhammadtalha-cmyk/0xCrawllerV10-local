"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { Artifact } from "@/lib/types";
import { extractFindings, languageForName, parseCsv } from "@/lib/reportParsing";
import { formatBytes } from "@/lib/format";
import { CodeBlock } from "./CodeBlock";
import { FindingsTable } from "./FindingsTable";
import { MarkdownReport } from "./MarkdownReport";
import { DownloadIcon } from "./Icons";

const MAX_PREVIEW_SIZE = 1.5 * 1024 * 1024; // 1.5 MB bounded preview

/**
 * Renders the body of a single artifact by content type:
 * markdown reports get real typography, JSON findings become a filterable
 * table, other JSON/CSV/log/text falls back to a syntax-highlighted block
 * so nothing is ever dumped as unstyled raw text.
 */
export function ArtifactBody({ artifact }: { artifact: Artifact }) {
  const [text, setText] = useState<string | null>(null);
  const [isTruncated, setIsTruncated] = useState(false);
  const [loadingFull, setLoadingFull] = useState(false);
  const [error, setError] = useState("");

  const isLarge = (artifact.size_bytes || 0) > MAX_PREVIEW_SIZE;

  useEffect(() => {
    setText(null);
    setIsTruncated(false);
    setLoadingFull(false);
    setError("");

    const fetchLimit = isLarge ? MAX_PREVIEW_SIZE : undefined;
    api.artifactText(artifact.id, fetchLimit)
      .then((resText) => {
        setText(resText);
        if (isLarge) setIsTruncated(true);
      })
      .catch((err: Error) => setError(err.message));
  }, [artifact.id, isLarge]);

  const handleLoadFull = async () => {
    setLoadingFull(true);
    try {
      const fullText = await api.artifactText(artifact.id);
      setText(fullText);
      setIsTruncated(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load full artifact");
    } finally {
      setLoadingFull(false);
    }
  };

  const language = useMemo(() => languageForName(artifact.name), [artifact.name]);

  if (error) return <div className="error-banner">{error}</div>;
  if (text === null) return <div className="empty-state"><div className="loader" />Loading document...</div>;

  return (
    <div className="artifact-body-wrapper">
      {isTruncated && (
        <div
          className="preview-banner"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "10px 14px",
            background: "rgba(255, 255, 255, 0.05)",
            borderRadius: "6px",
            marginBottom: "12px",
            border: "1px solid rgba(255, 255, 255, 0.1)",
          }}
        >
          <span style={{ fontSize: "13px" }}>
            Showing initial preview ({formatBytes(MAX_PREVIEW_SIZE)} of {formatBytes(artifact.size_bytes)}).
          </span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="btn secondary"
              onClick={handleLoadFull}
              disabled={loadingFull}
              style={{ padding: "4px 10px", fontSize: "12px" }}
            >
              {loadingFull ? "Loading..." : "Load full in browser"}
            </button>
            <a
              className="btn primary"
              href={api.artifactUrl(artifact.id, true)}
              download
              style={{
                padding: "4px 10px",
                fontSize: "12px",
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

      {renderArtifactContent(artifact, text, language, isTruncated)}
    </div>
  );
}

function renderArtifactContent(
  artifact: Artifact,
  text: string,
  language: string,
  isTruncated: boolean
) {
  if (artifact.kind === "report" || language === "markdown") {
    return <MarkdownReport markdown={text} />;
  }

  if (language === "json") {
    if (!isTruncated) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
        const findings = extractFindings(parsed);
        if (findings && findings.length) return <FindingsTable findings={findings} />;
        return <CodeBlock code={JSON.stringify(parsed, null, 2)} language="json" />;
      } catch {
        return <CodeBlock code={text} language="json" />;
      }
    }
    return <CodeBlock code={text} language="json" />;
  }

  if (language === "csv") {
    if (!isTruncated) {
      const { headers, rows } = parseCsv(text);
      if (headers.length) {
        return (
          <div className="findings-table-scroll">
            <table className="findings-table csv-table">
              <thead>
                <tr>
                  {headers.map((header, index) => (
                    <th key={index}>{header}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, rowIndex) => (
                  <tr key={rowIndex}>
                    {row.map((cell, cellIndex) => (
                      <td key={cellIndex}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }
    }
    return <CodeBlock code={text} language="csv" />;
  }

  return <CodeBlock code={text} language={language} />;
}
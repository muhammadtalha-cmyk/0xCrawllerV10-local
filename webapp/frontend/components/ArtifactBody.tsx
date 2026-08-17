"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { Artifact } from "@/lib/types";
import { extractFindings, languageForName, parseCsv } from "@/lib/reportParsing";
import { CodeBlock } from "./CodeBlock";
import { FindingsTable } from "./FindingsTable";
import { MarkdownReport } from "./MarkdownReport";

/**
 * Renders the body of a single artifact by content type:
 * markdown reports get real typography, JSON findings become a filterable
 * table, other JSON/CSV/log/text falls back to a syntax-highlighted block
 * so nothing is ever dumped as unstyled raw text.
 */
export function ArtifactBody({ artifact }: { artifact: Artifact }) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setText(null);
    setError("");
    api.artifactText(artifact.id).then(setText).catch((err: Error) => setError(err.message));
  }, [artifact.id]);

  const language = useMemo(() => languageForName(artifact.name), [artifact.name]);

  if (error) return <div className="error-banner">{error}</div>;
  if (text === null) return <div className="empty-state"><div className="loader" />Loading document...</div>;

  if (artifact.kind === "report" || language === "markdown") {
    return <MarkdownReport markdown={text} />;
  }

  if (language === "json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return <CodeBlock code={text} language="json" />;
    }
    const findings = extractFindings(parsed);
    if (findings && findings.length) return <FindingsTable findings={findings} />;
    return <CodeBlock code={JSON.stringify(parsed, null, 2)} language="json" />;
  }

  if (language === "csv") {
    const { headers, rows } = parseCsv(text);
    if (headers.length) {
      return (
        <div className="findings-table-scroll">
          <table className="findings-table csv-table">
            <thead><tr>{headers.map((header, index) => <th key={index}>{header}</th>)}</tr></thead>
            <tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody>
          </table>
        </div>
      );
    }
    return <CodeBlock code={text} language="csv" />;
  }

  return <CodeBlock code={text} language={language} />;
}
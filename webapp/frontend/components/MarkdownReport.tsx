"use client";

import type { ReactNode } from "react";
import { CodeBlock } from "./CodeBlock";
import { ExternalIcon } from "./Icons";

function inline(text: string): ReactNode[] {
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|\*[^*]+\*)/g;
  const parts = text.split(pattern).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`")) return <code key={index}>{part.slice(1, -1)}</code>;
    if (part.startsWith("*") && part.endsWith("*")) return <em key={index}>{part.slice(1, -1)}</em>;
    const link = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (link) return <a key={index} href={link[2]} target="_blank" rel="noreferrer">{link[1]} <ExternalIcon /></a>;
    return part;
  });
}

function cells(line: string): string[] {
  return line.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim());
}

function isSeparator(line: string): boolean {
  const values = cells(line);
  return values.length > 0 && values.every((value) => /^:?-{3,}:?$/.test(value));
}

export function MarkdownReport({ markdown }: { markdown: string }) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const output: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();
    if (!trimmed) { index += 1; continue; }

    if (trimmed.startsWith("```")) {
      const language = trimmed.slice(3).trim() || "text";
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith("```")) { body.push(lines[index]); index += 1; }
      index += 1;
      output.push(<CodeBlock key={`code-${index}`} language={language} code={body.join("\n")} />);
      continue;
    }

    if (trimmed.includes("|") && index + 1 < lines.length && isSeparator(lines[index + 1])) {
      const headers = cells(trimmed);
      const rows: string[][] = [];
      index += 2;
      while (index < lines.length && lines[index].trim().includes("|") && lines[index].trim()) {
        rows.push(cells(lines[index]));
        index += 1;
      }
      output.push(
        <div className="markdown-table-wrap" key={`table-${index}`}><table><thead><tr>{headers.map((header, cellIndex) => <th key={cellIndex}>{inline(header)}</th>)}</tr></thead><tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{headers.map((_, cellIndex) => <td key={cellIndex}>{inline(row[cellIndex] || "")}</td>)}</tr>)}</tbody></table></div>
      );
      continue;
    }

    const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      const content = inline(heading[2]);
      const key = `heading-${index}`;
      if (level === 1) output.push(<h1 key={key}>{content}</h1>);
      else if (level === 2) output.push(<h2 key={key}>{content}</h2>);
      else if (level === 3) output.push(<h3 key={key}>{content}</h3>);
      else output.push(<h4 key={key}>{content}</h4>);
      index += 1;
      continue;
    }

    if (/^[-*+]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length && /^[-*+]\s+/.test(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^[-*+]\s+/, ""));
        index += 1;
      }
      output.push(<ul key={`list-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{inline(item)}</li>)}</ul>);
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      const items: string[] = [];
      while (index < lines.length && /^\d+\.\s+/.test(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^\d+\.\s+/, ""));
        index += 1;
      }
      output.push(<ol key={`ordered-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{inline(item)}</li>)}</ol>);
      continue;
    }

    if (trimmed.startsWith(">")) {
      const quote: string[] = [];
      while (index < lines.length && lines[index].trim().startsWith(">")) {
        quote.push(lines[index].trim().replace(/^>\s?/, ""));
        index += 1;
      }
      output.push(<blockquote key={`quote-${index}`}>{inline(quote.join(" "))}</blockquote>);
      continue;
    }

    if (/^---+$/.test(trimmed)) {
      output.push(<hr key={`hr-${index}`} />);
      index += 1;
      continue;
    }

    const paragraph = [trimmed];
    index += 1;
    while (index < lines.length) {
      const next = lines[index].trim();
      if (!next || /^(#{1,6})\s+/.test(next) || /^[-*+]\s+/.test(next) || /^\d+\.\s+/.test(next) || next.startsWith("```") || next.startsWith(">") || (next.includes("|") && index + 1 < lines.length && isSeparator(lines[index + 1]))) break;
      paragraph.push(next);
      index += 1;
    }
    output.push(<p key={`paragraph-${index}`}>{inline(paragraph.join(" "))}</p>);
  }

  return <div className="markdown-report">{output}</div>;
}

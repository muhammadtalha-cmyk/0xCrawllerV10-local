"use client";

import { useState } from "react";

export function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard can be unavailable in restricted browser contexts.
    }
  }
  return (
    <div className="code-block">
      <div className="code-block-bar"><span>{language || "text"}</span><button onClick={copy}>{copied ? "Copied" : "Copy"}</button></div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

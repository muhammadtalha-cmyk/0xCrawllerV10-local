import { api } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import type { Artifact } from "@/lib/types";
import { ChevronIcon, FileIcon, ImageIcon } from "./Icons";

export function ArtifactList({ title, items, empty, onOpen }: { title: string; items: Artifact[]; empty: string; onOpen: (item: Artifact) => void }) {
  return (
    <section className="artifact-section">
      <div className="section-heading"><div><small>Artifacts</small><h2>{title}</h2></div><span>{items.length} files</span></div>
      {items.length ? (
        <div className="artifact-list">
          {items.map((item) => (
            <button key={item.id} onClick={() => onOpen(item)}>
              <span className="file-mark"><FileIcon /></span>
              <span><strong>{item.name}</strong><small>{item.step_key || "pipeline"} · {formatBytes(item.size_bytes)}</small></span>
              <ChevronIcon />
            </button>
          ))}
        </div>
      ) : (
        <div className="empty-state"><FileIcon /><h3>Nothing to show yet</h3><p>{empty}</p></div>
      )}
    </section>
  );
}

export function ScreenshotGrid({ items, onOpen }: { items: Artifact[]; onOpen: (item: Artifact) => void }) {
  return (
    <section className="artifact-section">
      <div className="section-heading"><div><small>Visual evidence</small><h2>Captured screenshots</h2></div><span>{items.length} images</span></div>
      {items.length ? (
        <div className="screenshot-grid">
          {items.map((item) => (
            <button key={item.id} onClick={() => onOpen(item)}>
              <div className="shot-image"><img src={api.artifactUrl(item.id)} alt={item.name} loading="lazy" /></div>
              <span><strong>{item.name}</strong><small>{formatBytes(item.size_bytes)}</small></span>
            </button>
          ))}
        </div>
      ) : (
        <div className="empty-state"><ImageIcon /><h3>No screenshots indexed</h3><p>HTTPX screenshots will appear here after reconnaissance.</p></div>
      )}
    </section>
  );
}
"use client";

import type { MouseEvent } from "react";
import { api } from "@/lib/api";
import type { Artifact } from "@/lib/types";
import { ArtifactBody } from "./ArtifactBody";
import { DownloadIcon, XIcon } from "./Icons";

export function ArtifactViewer({ artifact, onClose }: { artifact: Artifact; onClose: () => void }) {
  const isImage = artifact.kind === "screenshot" || artifact.kind === "image";

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="artifact-modal" onMouseDown={(event: MouseEvent<HTMLElement>) => event.stopPropagation()}>
        <header>
          <div><small>{artifact.kind}</small><h3>{artifact.name}</h3></div>
          <div className="modal-actions">
            <a href={api.artifactUrl(artifact.id, true)}><DownloadIcon /> Download</a>
            <button onClick={onClose} aria-label="Close"><XIcon /></button>
          </div>
        </header>
        <div className={`artifact-content ${isImage ? "image-preview" : "text-preview"}`}>
          {isImage ? <img src={api.artifactUrl(artifact.id)} alt={artifact.name} /> : <ArtifactBody artifact={artifact} />}
        </div>
      </section>
    </div>
  );
}
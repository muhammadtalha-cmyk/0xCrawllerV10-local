import Link from "next/link";
import type { Scan } from "@/lib/types";
import { ArrowIcon, ClockIcon, DatabaseIcon } from "./Icons";
import { StatusPill } from "./StatusPill";

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function ScanCard({ scan }: { scan: Scan }) {
  const completed = scan.steps.filter((step) => step.status === "completed").length;
  const artifacts = Object.values(scan.artifact_counts || {}).reduce((sum, value) => sum + value, 0);
  return (
    <Link href={`/scans/${scan.id}`} className="scan-card premium-scan-card">
      <div className="scan-card-top"><div><small>Authorized target</small><h3>{scan.target}</h3></div><StatusPill status={scan.status} /></div>
      <div className="scan-card-intel"><span><DatabaseIcon />{artifacts} artifacts</span><span>{completed}/4 modules</span></div>
      <div className="mini-progress"><span style={{ width: `${scan.progress}%` }} /></div>
      <div className="scan-card-bottom"><span><ClockIcon />{formatDate(scan.started_at)}</span><span>Open intelligence <ArrowIcon /></span></div>
    </Link>
  );
}

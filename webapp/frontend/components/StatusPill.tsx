import type { ScanStatus } from "@/lib/types";

export function StatusPill({ status }: { status: ScanStatus }) {
  return <span className={`status-pill status-${status}`}><span className="status-dot" />{status}</span>;
}

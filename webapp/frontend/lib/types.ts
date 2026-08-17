export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type StepStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface ScanStep {
  id: number;
  scan_id: string;
  step_key: string;
  name: string;
  position: number;
  status: StepStatus;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  exit_code: number | null;
  message: string | null;
}

export interface Scan {
  id: string;
  target: string;
  status: ScanStatus;
  current_step: string | null;
  progress: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  run_dir: string | null;
  cancel_requested: boolean;
  steps: ScanStep[];
  artifact_counts: Record<string, number>;
}

export interface ScanLog {
  id: number;
  scan_id: string;
  step_key: string | null;
  level: "info" | "success" | "warning" | "error";
  message: string;
  created_at: string;
}

export interface Artifact {
  id: string;
  scan_id: string;
  step_key: string | null;
  kind: "report" | "screenshot" | "image" | "data" | "log";
  name: string;
  relative_path: string;
  mime_type: string | null;
  size_bytes: number;
  created_at: string;
}

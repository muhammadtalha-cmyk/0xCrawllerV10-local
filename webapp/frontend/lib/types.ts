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

export interface CveFinding {
  product: string;
  version: string;
  cve: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | string;
  cvss: number | null;
  cvss_version?: string;
  description: string;
  source: string;
  hosts: string[];
  confidence?: string;
  evidence_source?: string;
}

export interface CveSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  products_scanned: number;
}

export interface Tool {
  id: number;
  name: string;
  version: string | null;
  category: string | null;
  description: string | null;
  enabled: boolean;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface ToolExecution {
  id: number;
  scan_id: string;
  tool_id: number | null;
  tool_name?: string;
  tool_version?: string;
  tool_category?: string;
  step_key: string | null;
  command: string | null;
  parameters: Record<string, unknown>;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  output_path: string | null;
  error_message: string | null;
  metadata?: Record<string, unknown>;
}

export interface SecurityModule {
  id: string;
  name: string;
  description: string;
  category: string;
  icon: string;
  status: "ready" | "busy" | "disabled";
}

export interface ModuleJob {
  id: string;
  user_id: string | null;
  module_type: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  result_location: string | null;
  created_at: string;
}

export interface ModuleRunResponse {
  job_id: string;
  module_type: string;
  target: string;
  status: string;
}



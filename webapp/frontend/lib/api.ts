import type {
  Artifact,
  Scan,
  ScanLog,
  SecurityModule,
  ModuleJob,
  ModuleRunResponse,
} from "./types";

export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL || ""
).replace(/\/$/, "");

async function request<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetch(
    `${API_URL}${path}`,
    {
      cache: "no-store",
      credentials: "include",
      ...init,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(init.headers || {}),
      },
    }
  );

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") {
        message = body.detail;
      }
    } catch {
      // Keep default.
    }
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

export const api = {
  listScans: () =>
    request<Scan[]>("/api/scans?limit=50"),

  getScan: (id: string) =>
    request<Scan>(`/api/scans/${id}`),

  createScan: (target: string) =>
    request<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ target, authorized: true }),
    }),

  cancelScan: (id: string) =>
    request<{ accepted: boolean }>(`/api/scans/${id}/cancel`, { method: "POST" }),

  getLogs: (id: string, afterId = 0) =>
    request<ScanLog[]>(`/api/scans/${id}/logs?after_id=${afterId}`),

  getArtifacts: (id: string) =>
    request<Artifact[]>(`/api/scans/${id}/artifacts`),

  artifactUrl: (id: string, download = false) => {
    const params = new URLSearchParams();
    if (download) params.set("download", "true");
    const query = params.toString();
    return `${API_URL}/api/artifacts/${id}${query ? `?${query}` : ""}`;
  },

  artifactText: async (id: string, maxBytes?: number) => {
    const url = new URL(`${API_URL}/api/artifacts/${id}/text`);
    if (maxBytes) url.searchParams.set("max_bytes", String(maxBytes));
    const response = await fetch(url.toString(), {
      cache: "no-store",
      credentials: "include",
      headers: { Accept: "text/plain" },
    });
    if (!response.ok) throw new Error(`Unable to open artifact (${response.status})`);
    return response.text();
  },

  getMetrics: (scanId: string) =>
    request<any>(`/api/scans/${scanId}/metrics`),

  getAssets: (scanId: string, limit = 50, offset = 0, q = "") =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/assets?limit=${limit}&offset=${offset}&q=${encodeURIComponent(q)}`
    ),

  getServices: (scanId: string, limit = 50, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/services?limit=${limit}&offset=${offset}`
    ),

  getTechnologies: (scanId: string, limit = 50, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/technologies?limit=${limit}&offset=${offset}`
    ),

  getEndpoints: (scanId: string, limit = 50, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/endpoints?limit=${limit}&offset=${offset}`
    ),

  getFindings: (scanId: string, limit = 50, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/findings?limit=${limit}&offset=${offset}`
    ),

  getCveFindings: (scanId: string, limit = 100, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/cve-findings?limit=${limit}&offset=${offset}`
    ),

  getRelationships: (scanId: string, limit = 50, offset = 0) =>
    request<{ total: number; items: any[] }>(
      `/api/scans/${scanId}/relationships?limit=${limit}&offset=${offset}`
    ),

  getReportSections: (scanId: string, reportType: string) =>
    request<any[]>(`/api/scans/${scanId}/reports/${reportType}`),

  // ------------------------------------------------------------------
  // SECURITY MODULES
  // ------------------------------------------------------------------

  getModules: () =>
    request<SecurityModule[]>("/api/modules"),

  runModule: (moduleName: string, target: string) =>
    request<ModuleRunResponse>(`/api/modules/${moduleName}/run`, {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  listModuleJobs: (limit = 50, offset = 0) =>
    request<ModuleJob[]>(`/api/modules/jobs?limit=${limit}&offset=${offset}`),

  getModuleJob: (jobId: string) =>
    request<ModuleJob>(`/api/modules/jobs/${jobId}`),

  getModuleJobResults: (jobId: string) =>
    request<any>(`/api/modules/jobs/${jobId}/results`),
};

export function scanSocketUrl(scanId: string): string {
  const base = API_URL.replace(/^http/, "ws");
  return `${base}/ws/scans/${scanId}`;
}

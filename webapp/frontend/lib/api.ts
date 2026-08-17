import type {
  Artifact,
  Scan,
  ScanLog,
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
    let message =
      `Request failed (${response.status})`;

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
      body: JSON.stringify({
        target,
        authorized: true,
      }),
    }),

  cancelScan: (id: string) =>
    request<{ accepted: boolean }>(
      `/api/scans/${id}/cancel`,
      {
        method: "POST",
      }
    ),

  getLogs: (
    id: string,
    afterId = 0
  ) =>
    request<ScanLog[]>(
      `/api/scans/${id}/logs?after_id=${afterId}`
    ),

  getArtifacts: (id: string) =>
    request<Artifact[]>(
      `/api/scans/${id}/artifacts`
    ),

  artifactUrl: (
    id: string,
    download = false
  ) => {
    const params = new URLSearchParams();

    if (download) {
      params.set("download", "true");
    }

    const query = params.toString();

    return `${API_URL}/api/artifacts/${id}${
      query ? `?${query}` : ""
    }`;
  },

  artifactText: async (id: string) => {
    const response = await fetch(
      `${API_URL}/api/artifacts/${id}/text`,
      {
        cache: "no-store",
        credentials: "include",
        headers: {
          Accept: "text/plain",
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Unable to open artifact (${response.status})`
      );
    }

    return response.text();
  },
};

export function scanSocketUrl(
  scanId: string
): string {
  const base = API_URL.replace(
    /^http/,
    "ws"
  );

  return `${base}/ws/scans/${scanId}`;
}
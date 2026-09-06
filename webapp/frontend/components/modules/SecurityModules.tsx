"use client";

import { useState, useEffect, useMemo, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { SecurityModule, ModuleJob } from "@/lib/types";
import {
  ShieldIcon,
  PlayIcon,
  TerminalIcon,
  CopyIcon,
  DownloadIcon,
  ActivityIcon,
} from "@/components/Icons";

const MODULE_ICONS: Record<string, string> = {
  subdomains: "🌐",
  technologies: "🔍",
  ports: "🔌",
  endpoints: "🕷",
  screenshots: "📸",
  cve: "🛡",
  waf: "🛡️",
  ssl: "🔒",
  dns_hygiene: "📑",
  takeover: "🎯",
  headers: "🛡️",
};

// Unified Minimalist Enterprise Palette (Single coherent theme across all capabilities)
const UNIFIED_THEME = {
  border: "var(--panel-border)",
  glow: "var(--accent-glow)",
  badge: "var(--panel-soft)",
  text: "var(--text)",
  muted: "var(--muted)",
  accent: "var(--accent)",
};

const MODULE_COLORS: Record<string, { border: string; glow: string; badge: string; text: string }> = new Proxy({}, {
  get: () => UNIFIED_THEME,
});

export function SecurityModules() {
  const [modules, setModules] = useState<SecurityModule[]>([]);
  const [jobs, setJobs] = useState<ModuleJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"modules" | "history">("modules");

  // Modal execution state
  const [selectedModule, setSelectedModule] = useState<SecurityModule | null>(null);
  const [targetDomain, setTargetDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [activeJob, setActiveJob] = useState<ModuleJob | null>(null);
  const [jobResults, setJobResults] = useState<any>(null);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [modalError, setModalError] = useState("");

  // Subdomain result filter
  const [subdomainSearch, setSubdomainSearch] = useState("");

  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      try {
        setLoading(true);
        const [mods, jobList] = await Promise.all([
          api.getModules().catch(() => []),
          api.listModuleJobs(30).catch(() => []),
        ]);
        if (!cancelled) {
          setModules(mods);
          setJobs(jobList);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchData();
    return () => { cancelled = true; };
  }, []);

  // Poll active job while running
  useEffect(() => {
    if (!activeJob || activeJob.status === "completed" || activeJob.status === "failed" || activeJob.status === "cancelled") {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await api.getModuleJob(activeJob.id);
        setActiveJob(updated);

        if (updated.status === "completed") {
          setResultsLoading(true);
          const res = await api.getModuleJobResults(updated.id);
          setJobResults(res);
          setResultsLoading(false);
          // Refresh history
          api.listModuleJobs(30).then(setJobs).catch(() => {});
        } else if (updated.status === "failed") {
          setModalError(updated.error_message || "Module execution failed");
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeJob]);

  const handleOpenModal = (mod: SecurityModule) => {
    setSelectedModule(mod);
    setTargetDomain("");
    setAuthorized(false);
    setActiveJob(null);
    setJobResults(null);
    setModalError("");
    setSubdomainSearch("");
  };

  const handleViewJobResults = async (job: ModuleJob) => {
    const mod = modules.find((m) => m.id === job.module_type) || {
      id: job.module_type,
      name: job.module_type.toUpperCase(),
      description: "",
      category: "Module",
      icon: "",
      status: "ready",
    };
    setSelectedModule(mod);
    setActiveJob(job);
    setModalError(job.error_message || "");
    setResultsLoading(true);

    if (job.status === "completed") {
      try {
        const res = await api.getModuleJobResults(job.id);
        setJobResults(res);
      } catch (err: any) {
        setModalError(err.message || "Failed to load results");
      }
    }
    setResultsLoading(false);
  };

  const handleStartRun = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedModule || !targetDomain.trim() || !authorized || submitting) return;

    setSubmitting(true);
    setModalError("");
    setJobResults(null);

    try {
      const resp = await api.runModule(selectedModule.id, targetDomain.trim());
      const job = await api.getModuleJob(resp.job_id);
      setActiveJob(job);
      setJobs((prev) => [job, ...prev]);
    } catch (err: any) {
      setModalError(err.message || "Failed to start module execution");
    } finally {
      setSubmitting(false);
    }
  };

  const filteredSubdomains = useMemo(() => {
    if (!jobResults?.subdomains) return [];
    if (!subdomainSearch.trim()) return jobResults.subdomains;
    const q = subdomainSearch.toLowerCase();
    return jobResults.subdomains.filter((s: any) =>
      s.subdomain.toLowerCase().includes(q) ||
      (s.ips && s.ips.some((ip: string) => ip.toLowerCase().includes(q)))
    );
  }, [jobResults, subdomainSearch]);

  const copySubdomainsToClipboard = () => {
    if (!jobResults?.subdomains) return;
    const text = jobResults.subdomains.map((s: any) => s.subdomain).join("\n");
    navigator.clipboard.writeText(text);
    alert(`Copied ${jobResults.subdomains.length} hostnames to clipboard.`);
  };

  const downloadJson = () => {
    if (!jobResults) return;
    const blob = new Blob([JSON.stringify(jobResults, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedModule?.id || "module"}-${activeJob?.target || "results"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="security-modules-section mt-8 mb-8">
      <div className="section-heading mb-6" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16 }}>
        <div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.2, color: "var(--accent, #7dd3fc)", marginBottom: 4 }}>
            <TerminalIcon />
            Modular Security Operations
          </div>
          <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0, letterSpacing: -0.5 }}>Security Modules</h2>
          <p style={{ margin: "4px 0 0", fontSize: 13, color: "var(--muted)" }}>
            Execute individual reconnaissance, fingerprinting, and audit engines independently on any target.
          </p>
        </div>

        <div style={{ display: "flex", background: "var(--panel-soft)", padding: 3, borderRadius: 8, border: "1px solid var(--panel-border)" }}>
          <button
            onClick={() => setActiveTab("modules")}
            style={{
              padding: "6px 14px",
              borderRadius: 6,
              border: "none",
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              background: activeTab === "modules" ? "var(--accent, #7dd3fc)" : "transparent",
              color: activeTab === "modules" ? "#0f172a" : "rgba(255,255,255,0.7)",
              transition: "all 0.15s ease",
            }}
          >
            Capabilities ({modules.length})
          </button>
          <button
            onClick={() => setActiveTab("history")}
            style={{
              padding: "6px 14px",
              borderRadius: 6,
              border: "none",
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              background: activeTab === "history" ? "var(--accent, #7dd3fc)" : "transparent",
              color: activeTab === "history" ? "#0f172a" : "rgba(255,255,255,0.7)",
              transition: "all 0.15s ease",
            }}
          >
            History ({jobs.length})
          </button>
        </div>
      </div>

      {activeTab === "modules" ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 18 }}>
          {modules.map((mod) => {
            const colors = MODULE_COLORS[mod.id] || {
              border: "rgba(255,255,255,0.15)",
              glow: "rgba(255,255,255,0.05)",
              badge: "rgba(255,255,255,0.1)",
              text: "#fff",
            };
            const iconChar = MODULE_ICONS[mod.id] || "⚡";

            return (
              <div
                key={mod.id}
                style={{
                  background: "var(--panel-solid)",
                  border: `1px solid ${colors.border}`,
                  borderRadius: 14,
                  padding: "22px 20px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  boxShadow: `0 8px 24px ${colors.glow}`,
                  position: "relative",
                  overflow: "hidden",
                  transition: "transform 0.2s ease, border-color 0.2s ease",
                }}
              >
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: colors.border }} />

                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                    <span style={{ fontSize: 28 }}>{iconChar}</span>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        textTransform: "uppercase",
                        letterSpacing: 0.8,
                        padding: "3px 8px",
                        borderRadius: 4,
                        background: colors.badge,
                        color: colors.text,
                        border: `1px solid ${colors.border}`,
                      }}
                    >
                      {mod.category}
                    </span>
                  </div>

                  <h3 style={{ fontSize: 17, fontWeight: 700, margin: "0 0 6px", color: "var(--text)" }}>
                    {mod.name}
                  </h3>
                  <p style={{ fontSize: 12.5, lineHeight: 1.5, color: "var(--muted)", margin: 0, minHeight: 48 }}>
                    {mod.description}
                  </p>
                </div>

                <div style={{ marginTop: 20, paddingTop: 14, borderTop: "1px solid var(--panel-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--muted)" }}>
                    Standalone Execution
                  </span>
                  <button
                    onClick={() => handleOpenModal(mod)}
                    style={{
                      background: colors.badge,
                      color: colors.text,
                      border: `1px solid ${colors.border}`,
                      padding: "6px 14px",
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 700,
                      cursor: "pointer",
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      transition: "all 0.15s ease",
                    }}
                  >
                    <PlayIcon /> Run Module
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ background: "var(--panel-solid)", border: "1px solid var(--panel-border)", borderRadius: 12, overflow: "hidden" }}>
          {jobs.length === 0 ? (
            <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--muted)" }}>
              No standalone module runs executed yet. Launch a module capability above to see records here.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, textAlign: "left" }}>
              <thead>
                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "var(--muted)" }}>
                  <th style={{ padding: "12px 16px" }}>Module</th>
                  <th style={{ padding: "12px 16px" }}>Target</th>
                  <th style={{ padding: "12px 16px" }}>Status</th>
                  <th style={{ padding: "12px 16px" }}>Started</th>
                  <th style={{ padding: "12px 16px" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => {
                  const colors = MODULE_COLORS[j.module_type] || { text: "#7dd3fc", badge: "rgba(125,211,252,0.1)" };
                  return (
                    <tr key={j.id} style={{ borderBottom: "1px solid var(--panel-border-subtle)" }}>
                      <td style={{ padding: "12px 16px", fontWeight: 600, color: colors.text }}>
                        {MODULE_ICONS[j.module_type] || "⚡"} {j.module_type}
                      </td>
                      <td style={{ padding: "12px 16px", color: "var(--text)", fontFamily: "monospace" }}>
                        {j.target}
                      </td>
                      <td style={{ padding: "12px 16px" }}>
                        <span
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            padding: "3px 8px",
                            borderRadius: 4,
                            textTransform: "uppercase",
                            background:
                              j.status === "completed"
                                ? "rgba(34, 197, 94, 0.15)"
                                : j.status === "running"
                                ? "rgba(56, 189, 248, 0.15)"
                                : "rgba(248, 113, 113, 0.15)",
                            color:
                              j.status === "completed"
                                ? "#4ade80"
                                : j.status === "running"
                                ? "#38bdf8"
                                : "#f87171",
                          }}
                        >
                          {j.status} {j.status === "running" && `(${j.progress}%)`}
                        </span>
                      </td>
                      <td style={{ padding: "12px 16px", color: "var(--muted)", fontSize: 12 }}>
                        {new Date(j.started_at).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "12px 16px" }}>
                        <button
                          onClick={() => handleViewJobResults(j)}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 4,
                            border: "1px solid var(--panel-border)",
                            background: "var(--panel-soft)",
                            color: "var(--text)",
                            fontSize: 11,
                            cursor: "pointer",
                          }}
                        >
                          View Results
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Execution / Results Modal */}
      {selectedModule && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.8)",
            backdropFilter: "blur(6px)",
            zIndex: 1000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 20,
          }}
        >
          <div
            style={{
              background: "var(--panel-solid)",
              border: `1px solid ${MODULE_COLORS[selectedModule.id]?.border || "rgba(255,255,255,0.2)"}`,
              borderRadius: 16,
              width: "100%",
              maxWidth: 820,
              maxHeight: "90vh",
              overflowY: "auto",
              boxShadow: "0 24px 48px rgba(0,0,0,0.8)",
              position: "relative",
              display: "flex",
              flexDirection: "column",
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: "18px 24px",
                borderBottom: "1px solid var(--panel-border)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontSize: 26 }}>{MODULE_ICONS[selectedModule.id] || "⚡"}</span>
                <div>
                  <h3 style={{ margin: 0, fontSize: 18, color: "var(--text)" }}>{selectedModule.name}</h3>
                  <span style={{ fontSize: 11, color: "var(--muted)" }}>
                    Modular Execution Engine
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedModule(null)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "rgba(255,255,255,0.6)",
                  fontSize: 22,
                  cursor: "pointer",
                }}
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: "24px", flex: 1 }}>
              {!activeJob ? (
                <form onSubmit={handleStartRun}>
                  <p style={{ fontSize: 13, color: "var(--text-soft)", marginTop: 0, marginBottom: 18 }}>
                    {selectedModule.description}
                  </p>

                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.8)", marginBottom: 6 }}>
                      Target Domain or Hostname
                    </label>
                    <div style={{ display: "flex", alignItems: "center", background: "rgba(0,0,0,0.4)", border: "1px solid var(--panel-border)", borderRadius: 8, overflow: "hidden" }}>
                      <span style={{ padding: "10px 14px", background: "var(--panel-soft)", color: "var(--muted)", fontSize: 13 }}>
                        https://
                      </span>
                      <input
                        type="text"
                        value={targetDomain}
                        onChange={(e) => setTargetDomain(e.target.value)}
                        placeholder="example.com"
                        required
                        style={{
                          flex: 1,
                          padding: "10px 14px",
                          background: "transparent",
                          border: "none",
                          color: "var(--text)",
                          fontSize: 14,
                          outline: "none",
                        }}
                      />
                    </div>
                  </div>

                  <label style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer", fontSize: 12.5, color: "var(--text-soft)", marginBottom: 20 }}>
                    <input
                      type="checkbox"
                      checked={authorized}
                      onChange={(e) => setAuthorized(e.target.checked)}
                      required
                    />
                    <span>I confirm authorization to perform security testing on this target.</span>
                  </label>

                  {modalError && (
                    <div style={{ padding: "10px 14px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 8, color: "#fca5a5", fontSize: 12, marginBottom: 16 }}>
                      {modalError}
                    </div>
                  )}

                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
                    <button
                      type="button"
                      onClick={() => setSelectedModule(null)}
                      style={{ padding: "9px 16px", borderRadius: 8, border: "1px solid var(--panel-border)", background: "transparent", color: "var(--text)", fontSize: 13, cursor: "pointer" }}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={!authorized || !targetDomain.trim() || submitting}
                      style={{
                        padding: "9px 20px",
                        borderRadius: 8,
                        border: "none",
                        background: "var(--accent, #7dd3fc)",
                        color: "#0f172a",
                        fontSize: 13,
                        fontWeight: 700,
                        cursor: authorized && targetDomain.trim() && !submitting ? "pointer" : "not-allowed",
                        opacity: authorized && targetDomain.trim() && !submitting ? 1 : 0.5,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <PlayIcon /> {submitting ? "Initializing..." : "Run Module"}
                    </button>
                  </div>
                </form>
              ) : (
                <div>
                  {/* Job Header & Live Progress */}
                  <div style={{ background: "var(--panel-soft)", border: "1px solid var(--panel-border)", borderRadius: 10, padding: "14px 18px", marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
                    <div>
                      <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>Active Target</div>
                      <strong style={{ fontSize: 16, color: "var(--text)", fontFamily: "monospace" }}>{activeJob.target}</strong>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span
                        style={{
                          fontSize: 11,
                          fontWeight: 700,
                          padding: "4px 10px",
                          borderRadius: 6,
                          textTransform: "uppercase",
                          background:
                            activeJob.status === "completed"
                              ? "rgba(34, 197, 94, 0.2)"
                              : activeJob.status === "running"
                              ? "rgba(56, 189, 248, 0.2)"
                              : "rgba(248, 113, 113, 0.2)",
                          color:
                            activeJob.status === "completed"
                              ? "#4ade80"
                              : activeJob.status === "running"
                              ? "#38bdf8"
                              : "#f87171",
                        }}
                      >
                        {activeJob.status} ({activeJob.progress}%)
                      </span>
                    </div>
                  </div>

                  {/* Running animation */}
                  {activeJob.status === "running" && (
                    <div style={{ textAlign: "center", padding: "30px 20px" }}>
                      <div className="loader" style={{ margin: "0 auto 16px" }} />
                      <h4 style={{ margin: "0 0 6px", fontSize: 15, color: "var(--text)" }}>
                        Executing {selectedModule.name}...
                      </h4>
                      <p style={{ margin: "0 0 16px", fontSize: 12.5, color: "var(--muted)" }}>
                        Running standalone containerized reconnaissance. Progress updates live.
                      </p>
                      <div style={{ width: "100%", height: 6, background: "rgba(255,255,255,0.1)", borderRadius: 3, overflow: "hidden", maxWidth: 400, margin: "0 auto" }}>
                        <div style={{ height: "100%", width: `${activeJob.progress}%`, background: "var(--accent, #7dd3fc)", transition: "width 0.4s ease" }} />
                      </div>
                    </div>
                  )}

                  {/* Failed state */}
                  {activeJob.status === "failed" && (
                    <div style={{ padding: "16px 20px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 10, color: "#fca5a5", fontSize: 13 }}>
                      <strong>Execution Error:</strong>
                      <p style={{ margin: "6px 0 0", fontFamily: "monospace", fontSize: 12 }}>
                        {activeJob.error_message || "Process terminated unexpectedly."}
                      </p>
                    </div>
                  )}

                  {/* Completed & Results Loading */}
                  {activeJob.status === "completed" && resultsLoading && (
                    <div style={{ textAlign: "center", padding: "40px" }}>
                      <div className="loader" style={{ margin: "0 auto 12px" }} />
                      <span>Parsing structured findings...</span>
                    </div>
                  )}

                  {/* Completed Results Display */}
                  {activeJob.status === "completed" && jobResults && (
                    <div>
                      {/* Subdomain Module Results */}
                      {selectedModule.id === "subdomains" && (
                        <div>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
                            <div>
                              <strong style={{ fontSize: 16, color: "var(--text)" }}>
                                {jobResults.total_subdomains || 0} Subdomains Discovered
                              </strong>
                              <span style={{ fontSize: 12, color: "#4ade80", marginLeft: 8 }}>
                                ({jobResults.active_subdomains || 0} active / resolving)
                              </span>
                            </div>

                            <div style={{ display: "flex", gap: 8 }}>
                              <button
                                onClick={copySubdomainsToClipboard}
                                style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--panel-border)", background: "var(--panel-soft)", color: "var(--text)", fontSize: 12, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 6 }}
                              >
                                <CopyIcon /> Copy Hosts
                              </button>
                              <button
                                onClick={downloadJson}
                                style={{ padding: "6px 12px", borderRadius: 6, border: "1px solid var(--panel-border)", background: "var(--panel-soft)", color: "var(--text)", fontSize: 12, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 6 }}
                              >
                                <DownloadIcon /> Export JSON
                              </button>
                            </div>
                          </div>

                          <input
                            type="text"
                            value={subdomainSearch}
                            onChange={(e) => setSubdomainSearch(e.target.value)}
                            placeholder="Filter discovered subdomains or IP addresses..."
                            style={{ width: "100%", padding: "8px 12px", borderRadius: 6, background: "var(--panel-soft)", border: "1px solid var(--panel-border)", color: "var(--text)", fontSize: 13, marginBottom: 14, outline: "none" }}
                          />

                          <div style={{ maxHeight: 340, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "rgba(255,255,255,0.6)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Subdomain</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>IP Address</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Type</th>
                                  <th style={{ padding: "8px 12px", textAlign: "right" }}>Status</th>
                                </tr>
                              </thead>
                              <tbody>
                                {filteredSubdomains.map((s: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#38bdf8", fontWeight: 600 }}>{s.subdomain}</td>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "var(--text-soft)" }}>{s.ips?.length ? s.ips.join(", ") : "—"}</td>
                                    <td style={{ padding: "8px 12px", color: "var(--muted)" }}>{s.dns_type || "A"}</td>
                                    <td style={{ padding: "8px 12px", textAlign: "right" }}>
                                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", background: s.status === "active" ? "rgba(34, 197, 94, 0.15)" : "rgba(255,255,255,0.05)", color: s.status === "active" ? "#4ade80" : "rgba(255,255,255,0.4)" }}>
                                        {s.status}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Technology Module Results */}
                      {selectedModule.id === "technologies" && (
                        <div>
                          <h4 style={{ margin: "0 0 12px", color: "var(--text)" }}>{jobResults.total_technologies || 0} Technologies Fingerprinted</h4>
                          <div style={{ maxHeight: 340, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "rgba(255,255,255,0.6)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Technology</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Version</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Category</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Evidence</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(jobResults.technologies || []).map((t: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontWeight: 700, color: "#c084fc" }}>{t.name}</td>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#4ade80" }}>{t.version || "—"}</td>
                                    <td style={{ padding: "8px 12px", color: "rgba(255,255,255,0.6)" }}>{t.category}</td>
                                    <td style={{ padding: "8px 12px", color: "var(--muted)", fontSize: 11 }}>{t.evidence}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Ports Module Results */}
                      {selectedModule.id === "ports" && (
                        <div>
                          <h4 style={{ margin: "0 0 12px", color: "var(--text)" }}>{jobResults.total_ports || 0} Open Ports Discovered</h4>
                          <div style={{ maxHeight: 340, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "rgba(255,255,255,0.6)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Port</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Protocol</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Service</th>
                                  <th style={{ padding: "8px 12px", textAlign: "right" }}>State</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(jobResults.ports || []).map((p: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", fontWeight: 700, color: "#34d399" }}>{p.port}</td>
                                    <td style={{ padding: "8px 12px", color: "rgba(255,255,255,0.6)" }}>{p.protocol}</td>
                                    <td style={{ padding: "8px 12px", color: "var(--text)" }}>{p.service}</td>
                                    <td style={{ padding: "8px 12px", textAlign: "right" }}>
                                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", background: "rgba(52, 211, 153, 0.15)", color: "#34d399" }}>
                                        {p.state}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Endpoints Module Results */}
                      {selectedModule.id === "endpoints" && (
                        <div>
                          <h4 style={{ margin: "0 0 12px", color: "var(--text)" }}>{jobResults.total_endpoints || 0} Endpoints Discovered</h4>
                          <div style={{ maxHeight: 340, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "rgba(255,255,255,0.6)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Method</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Path / Endpoint</th>
                                  <th style={{ padding: "8px 12px", textAlign: "right" }}>Category</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(jobResults.endpoints || []).map((e: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontWeight: 700, color: e.method === "POST" ? "#fbbf24" : "#38bdf8" }}>{e.method}</td>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "var(--text)", maxWidth: 450, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      <a href={e.url} target="_blank" rel="noreferrer" style={{ color: "inherit", textDecoration: "none" }}>{e.path}</a>
                                    </td>
                                    <td style={{ padding: "8px 12px", textAlign: "right", color: "var(--muted)", fontSize: 11 }}>{e.category}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Screenshots Module Results */}
                      {selectedModule.id === "screenshots" && (
                        <div>
                          <h4 style={{ margin: "0 0 12px", color: "var(--text)" }}>{jobResults.total_screenshots || 0} Screenshots Captured</h4>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 14 }}>
                            {(jobResults.screenshots || []).map((scr: any, idx: number) => (
                              <div key={idx} style={{ background: "rgba(0,0,0,0.5)", border: "1px solid var(--panel-border)", borderRadius: 8, overflow: "hidden" }}>
                                {scr.image_base64 ? (
                                  <img src={scr.image_base64} alt={scr.host} style={{ width: "100%", height: 180, objectFit: "cover" }} />
                                ) : (
                                  <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center", color: "rgba(255,255,255,0.3)" }}>
                                    No Image Available
                                  </div>
                                )}
                                <div style={{ padding: 10 }}>
                                  <strong style={{ fontSize: 13, color: "var(--text)", display: "block" }}>{scr.host}</strong>
                                  <span style={{ fontSize: 11, color: "var(--muted)" }}>HTTP {scr.status_code}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* CVE Module Results */}
                      {selectedModule.id === "cve" && (
                        <div>
                          <h4 style={{ margin: "0 0 12px", color: "var(--text)" }}>{jobResults.total_findings || 0} Vulnerabilities Identified</h4>
                          {jobResults.total_findings === 0 ? (
                            <div style={{ textAlign: "center", padding: "30px 20px", background: "rgba(34, 197, 94, 0.05)", border: "1px solid rgba(34, 197, 94, 0.2)", borderRadius: 8 }}>
                              <span style={{ fontSize: 32 }}>🛡️</span>
                              <h4 style={{ color: "#4ade80", margin: "8px 0 4px" }}>0 Known CVEs Found</h4>
                              <p style={{ margin: 0, fontSize: 12.5, color: "rgba(255,255,255,0.6)" }}>Scanned software components were verified against NVD and confirmed clean.</p>
                            </div>
                          ) : (
                            <div style={{ maxHeight: 340, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                                <thead>
                                  <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "rgba(255,255,255,0.6)" }}>
                                    <th style={{ padding: "8px 12px", textAlign: "left" }}>CVE ID</th>
                                    <th style={{ padding: "8px 12px", textAlign: "left" }}>Severity</th>
                                    <th style={{ padding: "8px 12px", textAlign: "left" }}>Product</th>
                                    <th style={{ padding: "8px 12px", textAlign: "left" }}>Description</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(jobResults.findings || []).map((f: any, idx: number) => (
                                    <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                      <td style={{ padding: "8px 12px", fontWeight: 700, color: "#f87171" }}>
                                        <a href={f.source_url} target="_blank" rel="noreferrer" style={{ color: "inherit", textDecoration: "underline" }}>{f.cve_id}</a>
                                      </td>
                                      <td style={{ padding: "8px 12px" }}>
                                        <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: f.severity === "CRITICAL" || f.severity === "HIGH" ? "rgba(239, 68, 68, 0.2)" : "rgba(251, 191, 36, 0.2)", color: f.severity === "CRITICAL" || f.severity === "HIGH" ? "#f87171" : "#fbbf24" }}>
                                          {f.severity}
                                        </span>
                                      </td>
                                      <td style={{ padding: "8px 12px", color: "var(--text)" }}>{f.product} {f.version}</td>
                                      <td style={{ padding: "8px 12px", color: "rgba(255,255,255,0.6)", fontSize: 11, maxWidth: 320 }}>{f.description}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}

                      {/* 🛡️ WAF & CDN Results */}
                      {selectedModule.id === "waf" && (
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "16px 20px", background: jobResults.detected ? "rgba(251, 146, 60, 0.1)" : "rgba(56, 189, 248, 0.1)", border: `1px solid ${jobResults.detected ? "rgba(251, 146, 60, 0.3)" : "rgba(56, 189, 248, 0.3)"}`, borderRadius: 10, marginBottom: 18 }}>
                            <span style={{ fontSize: 32 }}>{jobResults.detected ? "🛡️" : "🌐"}</span>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: jobResults.detected ? "#fb923c" : "#38bdf8" }}>
                                {jobResults.detected ? "Firewall Protection Detected" : "Direct Edge / No WAF Detected"}
                              </div>
                              <strong style={{ fontSize: 18, color: "var(--text)" }}>
                                {jobResults.detected ? `${jobResults.firewall} (${jobResults.manufacturer})` : "Direct Origin / Unshielded"}
                              </strong>
                            </div>
                          </div>

                          {jobResults.raw_log_summary && (
                            <div style={{ background: "rgba(0,0,0,0.4)", border: "1px solid var(--panel-border)", borderRadius: 8, padding: 14, fontFamily: "monospace", fontSize: 12, color: "var(--text-soft)" }}>
                              <pre style={{ margin: 0 }}>{jobResults.raw_log_summary}</pre>
                            </div>
                          )}
                        </div>
                      )}

                      {/* 🔒 SSL / TLS Results */}
                      {selectedModule.id === "ssl" && (
                        <div>
                          {jobResults.has_certificate ? (
                            <div>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 18 }}>
                                <div style={{ background: "var(--panel-soft)", border: "1px solid var(--panel-border)", padding: 12, borderRadius: 8 }}>
                                  <div style={{ fontSize: 11, color: "var(--muted)" }}>Certificate Status</div>
                                  <strong style={{ fontSize: 16, color: jobResults.certificate?.status === "Valid" ? "#4ade80" : "#f87171" }}>
                                    {jobResults.certificate?.status}
                                  </strong>
                                </div>
                                <div style={{ background: "var(--panel-soft)", border: "1px solid var(--panel-border)", padding: 12, borderRadius: 8 }}>
                                  <div style={{ fontSize: 11, color: "var(--muted)" }}>Days Remaining</div>
                                  <strong style={{ fontSize: 16, color: "#2dd4bf" }}>
                                    {jobResults.certificate?.days_remaining !== null ? `${jobResults.certificate?.days_remaining} days` : "—"}
                                  </strong>
                                </div>
                                <div style={{ background: "var(--panel-soft)", border: "1px solid var(--panel-border)", padding: 12, borderRadius: 8 }}>
                                  <div style={{ fontSize: 11, color: "var(--muted)" }}>TLS Version</div>
                                  <strong style={{ fontSize: 16, color: "#38bdf8" }}>{jobResults.certificate?.tls_version}</strong>
                                </div>
                              </div>

                              <div style={{ background: "rgba(0,0,0,0.3)", border: "1px solid var(--panel-border)", borderRadius: 8, padding: 16, marginBottom: 16 }}>
                                <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: 8, fontSize: 12.5 }}>
                                  <span style={{ color: "var(--muted)" }}>Subject CN:</span>
                                  <strong style={{ color: "var(--text)" }}>{jobResults.certificate?.subject_cn}</strong>
                                  <span style={{ color: "var(--muted)" }}>Issuer:</span>
                                  <span style={{ color: "#2dd4bf" }}>{jobResults.certificate?.issuer_cn}</span>
                                  <span style={{ color: "var(--muted)" }}>Valid To:</span>
                                  <span style={{ color: "var(--text)" }}>{jobResults.certificate?.valid_to}</span>
                                  <span style={{ color: "var(--muted)" }}>Cipher Suite:</span>
                                  <span style={{ color: "var(--text-soft)", fontFamily: "monospace" }}>{jobResults.certificate?.cipher_suite}</span>
                                </div>
                              </div>

                              {jobResults.certificate?.sans?.length > 0 && (
                                <div>
                                  <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>Subject Alternative Names ({jobResults.certificate.sans.length})</div>
                                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, maxHeight: 120, overflowY: "auto" }}>
                                    {jobResults.certificate.sans.map((san: string, idx: number) => (
                                      <span key={idx} style={{ padding: "2px 8px", borderRadius: 4, background: "rgba(45, 212, 191, 0.1)", border: "1px solid rgba(45, 212, 191, 0.2)", color: "#2dd4bf", fontSize: 11, fontFamily: "monospace" }}>
                                        {san}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          ) : (
                            <div style={{ textAlign: "center", padding: "30px", color: "#f87171" }}>
                              Failed to establish TLS handshake: {jobResults.error || "Port 443 closed or unreachable"}
                            </div>
                          )}
                        </div>
                      )}

                      {/* 📑 DNS & Email Security Hygiene Results */}
                      {selectedModule.id === "dns_hygiene" && (
                        <div>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 20px", background: "rgba(129, 140, 248, 0.1)", border: "1px solid rgba(129, 140, 248, 0.3)", borderRadius: 10, marginBottom: 18 }}>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "#818cf8" }}>Email Spoofing Resilience</div>
                              <strong style={{ fontSize: 17, color: "var(--text)" }}>{jobResults.security_posture}</strong>
                            </div>
                            <span style={{ fontSize: 24, fontWeight: 800, padding: "4px 14px", borderRadius: 8, background: jobResults.overall_grade.startsWith("A") ? "rgba(34, 197, 94, 0.2)" : "rgba(248, 113, 113, 0.2)", color: jobResults.overall_grade.startsWith("A") ? "#4ade80" : "#f87171" }}>
                              {jobResults.overall_grade}
                            </span>
                          </div>

                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 18 }}>
                            <div style={{ background: "rgba(0,0,0,0.3)", border: "1px solid var(--panel-border)", borderRadius: 8, padding: 14 }}>
                              <div style={{ fontSize: 11, color: "var(--muted)" }}>SPF Policy</div>
                              <strong style={{ fontSize: 14, color: jobResults.spf?.status === "Present" ? "#4ade80" : "#f87171" }}>{jobResults.spf?.mechanism}</strong>
                              <div style={{ fontSize: 11, fontFamily: "monospace", color: "rgba(255,255,255,0.6)", marginTop: 6, wordBreak: "break-all" }}>{jobResults.spf?.record || "No SPF record set"}</div>
                            </div>

                            <div style={{ background: "rgba(0,0,0,0.3)", border: "1px solid var(--panel-border)", borderRadius: 8, padding: 14 }}>
                              <div style={{ fontSize: 11, color: "var(--muted)" }}>DMARC Policy</div>
                              <strong style={{ fontSize: 14, color: jobResults.dmarc?.status === "Present" ? "#818cf8" : "#f87171" }}>Policy: {jobResults.dmarc?.policy}</strong>
                              <div style={{ fontSize: 11, fontFamily: "monospace", color: "rgba(255,255,255,0.6)", marginTop: 6, wordBreak: "break-all" }}>{jobResults.dmarc?.record || "No DMARC record set"}</div>
                            </div>
                          </div>

                          {jobResults.mx_records?.length > 0 && (
                            <div>
                              <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 6 }}>Mail Exchange Servers (MX)</div>
                              <div style={{ border: "1px solid var(--panel-border)", borderRadius: 8, overflow: "hidden" }}>
                                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                                  <tbody>
                                    {jobResults.mx_records.map((mx: any, idx: number) => (
                                      <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                        <td style={{ padding: "6px 12px", color: "var(--muted)", width: 40 }}>#{mx.priority}</td>
                                        <td style={{ padding: "6px 12px", fontFamily: "monospace", color: "var(--text)" }}>{mx.server}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* 🎯 Subdomain Takeover Results */}
                      {selectedModule.id === "takeover" && (
                        <div>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 18px", background: jobResults.vulnerable_count > 0 ? "rgba(239, 68, 68, 0.15)" : "rgba(34, 197, 94, 0.1)", border: `1px solid ${jobResults.vulnerable_count > 0 ? "rgba(239, 68, 68, 0.3)" : "rgba(34, 197, 94, 0.2)"}`, borderRadius: 10, marginBottom: 16 }}>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: jobResults.vulnerable_count > 0 ? "#f87171" : "#4ade80" }}>
                                Takeover Threat Evaluation
                              </div>
                              <strong style={{ fontSize: 16, color: "var(--text)" }}>
                                {jobResults.vulnerable_count > 0 ? `${jobResults.vulnerable_count} Vulnerable Dangling CNAMEs Detected!` : "No Dangling Cloud Pointers Found"}
                              </strong>
                            </div>
                            <span style={{ padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, background: jobResults.vulnerable_count > 0 ? "#f87171" : "#4ade80", color: "#0f172a" }}>
                              {jobResults.overall_status}
                            </span>
                          </div>

                          <div style={{ maxHeight: 300, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "var(--muted)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Subdomain</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>CNAME Target</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Provider</th>
                                  <th style={{ padding: "8px 12px", textAlign: "right" }}>Status</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(jobResults.items || []).map((item: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "var(--text)" }}>{item.subdomain}</td>
                                    <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#e879f9" }}>{item.cname}</td>
                                    <td style={{ padding: "8px 12px", color: "var(--text-soft)" }}>{item.provider}</td>
                                    <td style={{ padding: "8px 12px", textAlign: "right" }}>
                                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: item.status === "VULNERABLE" ? "rgba(239, 68, 68, 0.2)" : "rgba(255,255,255,0.05)", color: item.status === "VULNERABLE" ? "#f87171" : "#4ade80" }}>
                                        {item.status}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* 🛡️ HTTP Security Headers Results */}
                      {selectedModule.id === "headers" && (
                        <div>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 20px", background: "rgba(56, 189, 248, 0.1)", border: "1px solid rgba(56, 189, 248, 0.3)", borderRadius: 10, marginBottom: 16 }}>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "#38bdf8" }}>HTTP Header Hardening</div>
                              <strong style={{ fontSize: 16, color: "var(--text)" }}>{jobResults.passed_count} of {jobResults.headers?.length} Security Headers Configured ({jobResults.score}%)</strong>
                            </div>
                            <span style={{ fontSize: 24, fontWeight: 800, padding: "4px 14px", borderRadius: 8, background: jobResults.grade.startsWith("A") ? "rgba(34, 197, 94, 0.2)" : jobResults.grade === "B" ? "rgba(56, 189, 248, 0.2)" : "rgba(248, 113, 113, 0.2)", color: jobResults.grade.startsWith("A") ? "#4ade80" : jobResults.grade === "B" ? "#38bdf8" : "#f87171" }}>
                              {jobResults.grade}
                            </span>
                          </div>

                          <div style={{ maxHeight: 320, overflowY: "auto", border: "1px solid var(--panel-border)", borderRadius: 8 }}>
                            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                              <thead>
                                <tr style={{ background: "var(--panel-soft)", borderBottom: "1px solid var(--panel-border)", color: "var(--muted)" }}>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Security Header</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Status</th>
                                  <th style={{ padding: "8px 12px", textAlign: "left" }}>Configured Value / Recommendation</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(jobResults.headers || []).map((h: any, idx: number) => (
                                  <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                                    <td style={{ padding: "8px 12px", fontWeight: 700, color: "var(--text)" }}>
                                      {h.name}
                                      <div style={{ fontSize: 10, color: "var(--muted)", fontFamily: "monospace" }}>{h.header}</div>
                                    </td>
                                    <td style={{ padding: "8px 12px" }}>
                                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: h.status === "PASS" ? "rgba(34, 197, 94, 0.2)" : "rgba(248, 113, 113, 0.2)", color: h.status === "PASS" ? "#4ade80" : "#f87171" }}>
                                        {h.status}
                                      </span>
                                    </td>
                                    <td style={{ padding: "8px 12px", fontSize: 11 }}>
                                      {h.status === "PASS" ? (
                                        <span style={{ fontFamily: "monospace", color: "#4ade80" }}>{h.value}</span>
                                      ) : (
                                        <span style={{ color: "var(--muted)" }}>Recommended: <code style={{ color: "#38bdf8" }}>{h.recommended}</code></span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Modal Footer actions */}
                      <div style={{ marginTop: 20, paddingTop: 14, borderTop: "1px solid var(--panel-border)", display: "flex", justifyContent: "flex-end", gap: 10 }}>
                        <button
                          onClick={() => { setActiveJob(null); setJobResults(null); }}
                          style={{ padding: "8px 14px", borderRadius: 6, border: "1px solid rgba(255,255,255,0.2)", background: "transparent", color: "var(--text)", fontSize: 12, cursor: "pointer" }}
                        >
                          Run Another Target
                        </button>
                        <button
                          onClick={() => setSelectedModule(null)}
                          style={{ padding: "8px 16px", borderRadius: 6, border: "none", background: "var(--accent, #7dd3fc)", color: "#0f172a", fontSize: 12, fontWeight: 700, cursor: "pointer" }}
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

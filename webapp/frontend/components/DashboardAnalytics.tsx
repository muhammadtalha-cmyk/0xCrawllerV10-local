"use client";

import { useEffect, useMemo, useState } from "react";
import type { Scan } from "@/lib/types";
import { api } from "@/lib/api";
import {
  computeSeverityCounts,
  extractFindings,
  type Finding,
  type Severity,
} from "@/lib/reportParsing";
import { SeverityChart } from "@/components/SeverityChart";
import {
  RadarIcon,
  ShieldIcon,
  ShieldAlertIcon,
} from "@/components/Icons";

const EMPTY_SEVERITIES: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  unknown: 0,
};

const STATUS_COLOR: Record<string, string> = {
  completed: "var(--green)",
  running: "var(--cyan)",
  queued: "var(--blue)",
  failed: "var(--red)",
  cancelled: "var(--muted)",
};

// How many completed scans we'll pull vulnerability findings for. Every
// entry costs one artifacts-list call plus (if present) one findings-file
// fetch, so this keeps the dashboard fast on accounts with a long history
// while still reflecting real data rather than a single sample.
const FINDINGS_SAMPLE_SIZE = 20;

interface ScanFindingsSample {
  scan: Scan;
  count: number;
}

export function DashboardAnalytics({ scans }: { scans: Scan[] }) {
  const [severityTotals, setSeverityTotals] = useState<Record<Severity, number> | null>(null);
  const [perScanFindings, setPerScanFindings] = useState<ScanFindingsSample[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [findingsError, setFindingsError] = useState("");

  const completedScans = useMemo(
    () =>
      scans
        .filter((scan) => scan.status === "completed")
        .sort(
          (a, b) =>
            new Date(b.completed_at || b.started_at).getTime() -
            new Date(a.completed_at || a.started_at).getTime()
        ),
    [scans]
  );

  useEffect(() => {
    let cancelled = false;

    if (!completedScans.length) {
      setSeverityTotals({ ...EMPTY_SEVERITIES });
      setPerScanFindings([]);
      setFindingsLoading(false);
      return;
    }

    setFindingsLoading(true);
    setFindingsError("");

    const sample = completedScans.slice(0, FINDINGS_SAMPLE_SIZE);

    const loadFindings = async () => {
      try {
        const results = await Promise.all(
          sample.map(async (scan) => {
            try {
              const metrics = await api.getMetrics(scan.id);
              return { scan, metrics };
            } catch {
              return { scan, metrics: null };
            }
          })
        );

        if (cancelled) return;

        const totals: Record<Severity, number> = { ...EMPTY_SEVERITIES };
        const perScan: ScanFindingsSample[] = [];

        for (const { scan, metrics } of results) {
          if (!metrics) continue;
          
          totals.critical += metrics.severity_critical || 0;
          totals.high += metrics.severity_high || 0;
          totals.medium += metrics.severity_medium || 0;
          totals.low += metrics.severity_low || 0;
          totals.info += metrics.severity_info || 0;
          
          const scanTotal = (metrics.severity_critical || 0) + (metrics.severity_high || 0) + (metrics.severity_medium || 0) + (metrics.severity_low || 0) + (metrics.severity_info || 0);
          perScan.push({ scan, count: scanTotal });
        }

        setSeverityTotals(totals);
        setPerScanFindings(perScan.reverse());
      } catch (err) {
        if (!cancelled) {
          setFindingsError(
            err instanceof Error ? err.message : "Unable to aggregate findings"
          );
        }
      } finally {
        if (!cancelled) {
          setFindingsLoading(false);
        }
      }
    };

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [completedScans]);

  const statusCounts = useMemo(() => {
    const base = { completed: 0, running: 0, queued: 0, failed: 0, cancelled: 0 };
    for (const scan of scans) {
      if (scan.status in base) {
        (base as Record<string, number>)[scan.status] += 1;
      }
    }
    return base;
  }, [scans]);

  const totalScans = scans.length;
  const totalFindings = severityTotals
    ? Object.values(severityTotals).reduce((sum, value) => sum + value, 0)
    : 0;
  const criticalHigh = severityTotals
    ? severityTotals.critical + severityTotals.high
    : 0;

  // Scan launches bucketed by day, last 14 days.
  const activityBuckets = useMemo(() => {
    const days: { key: string; label: string; count: number }[] = [];
    const now = new Date();

    for (let i = 13; i >= 0; i -= 1) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const key = date.toISOString().slice(0, 10);
      days.push({
        key,
        label: date.toLocaleDateString(undefined, { day: "2-digit", month: "short" }),
        count: 0,
      });
    }

    const byKey = new Map(days.map((day) => [day.key, day]));

    for (const scan of scans) {
      if (!scan.started_at) continue;
      const key = new Date(scan.started_at).toISOString().slice(0, 10);
      const bucket = byKey.get(key);
      if (bucket) bucket.count += 1;
    }

    return days;
  }, [scans]);

  const maxActivity = Math.max(1, ...activityBuckets.map((day) => day.count));
  const maxSeverityBar = severityTotals
    ? Math.max(
        1,
        severityTotals.critical,
        severityTotals.high,
        severityTotals.medium,
        severityTotals.low,
        severityTotals.info
      )
    : 1;
  const maxPerScanFindings = Math.max(1, ...perScanFindings.map((entry) => entry.count));

  const statusEntries = [
    ["completed", statusCounts.completed],
    ["running", statusCounts.running],
    ["queued", statusCounts.queued],
    ["failed", statusCounts.failed],
    ["cancelled", statusCounts.cancelled],
  ] as const;

  let cursor = 0;
  const statusGradient = totalScans
    ? `conic-gradient(${statusEntries
        .filter(([, value]) => value > 0)
        .map(([status, value]) => {
          const start = cursor;
          cursor += (value / totalScans) * 100;
          return `${STATUS_COLOR[status]} ${start}% ${cursor}%`;
        })
        .join(",")})`
    : "conic-gradient(var(--panel-border) 0 100%)";

  return (
    <section className="dashboard-analytics">
      <div className="section-heading mb-4">
        <div>
          <small>Dashboard analytics</small>
          <h2>Operational Intelligence</h2>
        </div>
        <span>{totalScans} scans tracked</span>
      </div>

      <div className="analytics-stat-row">
        <article className="analytics-stat">
          <span className="analytics-stat-icon tone-blue">
            <RadarIcon />
          </span>
          <div>
            <small>Total Scans</small>
            <strong>{totalScans}</strong>
          </div>
        </article>

        <article className="analytics-stat">
          <span className="analytics-stat-icon tone-green">
            <ShieldIcon />
          </span>
          <div>
            <small>Completed</small>
            <strong>{statusCounts.completed}</strong>
          </div>
        </article>

        <article className="analytics-stat">
          <span className="analytics-stat-icon tone-red">
            <ShieldAlertIcon />
          </span>
          <div>
            <small>Failed</small>
            <strong>{statusCounts.failed}</strong>
          </div>
        </article>

        <article className="analytics-stat">
          <span className="analytics-stat-icon tone-amber">
            <ShieldAlertIcon />
          </span>
          <div>
            <small>Vulnerabilities Found</small>
            <strong>{findingsLoading ? "…" : totalFindings}</strong>
          </div>
        </article>
      </div>

      <div className="analytics-grid-2">
        <div className="intel-panel analytics-panel">
          <header className="panel-heading">
            <div>
              <small>Scan activity</small>
              <h3>Assessments launched — last 14 days</h3>
            </div>
          </header>
          <div className="finding-timeline">
            {activityBuckets.map((day) => (
              <div key={day.key} title={`${day.label}: ${day.count} scan${day.count === 1 ? "" : "s"}`}>
                <i>
                  <b style={{ height: `${Math.max(4, (day.count / maxActivity) * 100)}%` }} />
                </i>
                <strong>{day.count}</strong>
                <span>{day.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="intel-panel analytics-panel">
          <header className="panel-heading">
            <div>
              <small>Findings</small>
              <h3>By severity</h3>
            </div>
            <span>{findingsLoading ? "…" : `${totalFindings} total`}</span>
          </header>
          {findingsLoading ? (
            <div className="empty-state" style={{ minHeight: 150 }}>
              <div className="loader" />
              Aggregating findings...
            </div>
          ) : (
            <div className="severity-bars severity-bars-5">
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((severity) => {
                const value = severityTotals?.[severity] ?? 0;
                const height = Math.max(4, (value / maxSeverityBar) * 100);
                return (
                  <div key={severity}>
                    <span>{value}</span>
                    <i>
                      <b className={severity} style={{ height: `${height}%` }} />
                    </i>
                    <strong style={{ textTransform: "capitalize" }}>{severity}</strong>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div className="analytics-grid-3">
        <div className="intel-panel analytics-panel">
          <header className="panel-heading">
            <div>
              <small>Scan outcomes</small>
              <h3>Status breakdown</h3>
            </div>
          </header>
          <div className="risk-donut-layout">
            <div className="risk-donut" style={{ background: statusGradient }}>
              <div>
                <strong>{totalScans}</strong>
                <small>scans</small>
              </div>
            </div>
            <div className="risk-legend">
              {statusEntries.map(([status, value]) => (
                <div key={status}>
                  <i className="severity-dot" style={{ background: STATUS_COLOR[status] }} />
                  <span style={{ textTransform: "capitalize" }}>{status}</span>
                  <strong>{value}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="intel-panel analytics-panel analytics-panel-center">
          <header className="panel-heading">
            <div>
              <small>Risk exposure</small>
              <h3>Critical + high</h3>
            </div>
          </header>
          <div className="analytics-big-number tone-red">
            <ShieldAlertIcon />
            <strong>{findingsLoading ? "…" : criticalHigh}</strong>
            <span>
              Critical and high severity findings across the last{" "}
              {perScanFindings.length || 0} completed scans
            </span>
          </div>
        </div>

        <div className="intel-panel analytics-panel">
          <header className="panel-heading">
            <div>
              <small>Risk intelligence</small>
              <h3>Severity distribution</h3>
            </div>
          </header>
          {findingsLoading ? (
            <div className="empty-state" style={{ minHeight: 150 }}>
              <div className="loader" />
              Loading...
            </div>
          ) : (
            <SeverityChart counts={severityTotals || { ...EMPTY_SEVERITIES }} />
          )}
        </div>
      </div>

      {perScanFindings.length > 0 && (
        <div className="intel-panel analytics-panel analytics-panel-wide">
          <header className="panel-heading">
            <div>
              <small>Findings</small>
              <h3>By recent scan</h3>
            </div>
            <span>Most recent {perScanFindings.length} completed scans</span>
          </header>
          <div className="finding-timeline">
            {perScanFindings.map(({ scan, count }) => (
              <div key={scan.id} title={`${scan.target}: ${count} finding${count === 1 ? "" : "s"}`}>
                <i>
                  <b style={{ height: `${Math.max(4, (count / maxPerScanFindings) * 100)}%` }} />
                </i>
                <strong>{count}</strong>
                <span>{scan.target.length > 12 ? `${scan.target.slice(0, 11)}…` : scan.target}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {findingsError && <div className="error-banner mt-4">{findingsError}</div>}
    </section>
  );
}

"use client";

import {
  type ChangeEvent,
  type FormEvent,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Header } from "@/components/Header";
import {
  PlayIcon,
  ShieldIcon,
  RadarIcon,
  DatabaseIcon,
  ActivityIcon,
} from "@/components/Icons";
import { ScanCard } from "@/components/ScanCard";
import { DashboardAnalytics } from "@/components/DashboardAnalytics";
import { SecurityModules } from "@/components/modules/SecurityModules";
import type { Scan } from "@/lib/types";
import { api } from "@/lib/api";

export default function DashboardPage() {
  const router = useRouter();
  const { user, loading: authLoading } = useAuth();

  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  // Authentication guard
  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/login");
    }
  }, [user, authLoading, router]);

  // Load scan history
  useEffect(() => {
    if (authLoading || !user) {
      return;
    }

    let cancelled = false;

    const loadScans = async () => {
      try {
        setLoading(true);
        setError("");

        const data = await api.listScans();

        if (!cancelled) {
          setScans(Array.isArray(data) ? data : []);
        }
      } catch (err) {
        if (!cancelled) {
          console.error("Failed to load scans:", err);
          setError(err instanceof Error ? err.message : "Unable to load scan history");
          setScans([]);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    loadScans();

    return () => {
      cancelled = true;
    };
  }, [user, authLoading]);

  const historyMetrics = useMemo(
    () => ({
      total: scans.length,
      completed: scans.filter((scan) => scan.status === "completed").length,
      running: scans.filter((scan) => scan.status === "running" || scan.status === "queued").length,
      artifacts: scans.reduce(
        (sum, scan) =>
          sum +
          Object.values(scan.artifact_counts || {}).reduce(
            (inner, value) => inner + Number(value),
            0
          ),
        0
      ),
    }),
    [scans]
  );

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!authorized || !target.trim() || submitting) {
      return;
    }

    setSubmitting(true);
    setError("");

    try {
      const scan = await api.createScan(target.trim());
      if (!scan?.id) {
        throw new Error("The server did not return a scan ID.");
      }
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      console.error("Failed to create scan:", err);
      setError(err instanceof Error ? err.message : "Unable to start scan");
      setSubmitting(false);
    }
  }

  if (authLoading) {
    return (
      <main className="shell">
        <Header />
        <div className="empty-state page-loading">
          <div className="loader" />
          Verifying session...
        </div>
      </main>
    );
  }

  if (!user) {
    return (
      <main className="shell">
        <Header />
        <div className="empty-state page-loading">
          <div className="loader" />
          Redirecting to login...
        </div>
      </main>
    );
  }

  return (
    <main className="shell">
      <Header />

      {/* High-level Global System Status */}
      <section className="home-metrics mt-6">
        <article>
          <ActivityIcon />
          <div>
            <small>Active Targets</small>
            <strong>{historyMetrics.total}</strong>
          </div>
        </article>

        <article>
          <ShieldIcon />
          <div>
            <small>Completed Assessments</small>
            <strong>{historyMetrics.completed}</strong>
          </div>
        </article>

        <article>
          <RadarIcon />
          <div>
            <small>Active Scans</small>
            <strong>{historyMetrics.running}</strong>
          </div>
        </article>

        <article>
          <DatabaseIcon />
          <div>
            <small>Consolidated Evidence</small>
            <strong>{historyMetrics.artifacts}</strong>
          </div>
        </article>
      </section>

      {/* Launch assessment form */}
      <form className="launch-card premium-launch-card mt-6" onSubmit={submit}>
        <div className="launch-card-head">
          <div>
            <small>Orchestrator Controls</small>
            <h2>Start New Assessment</h2>
          </div>
          <span className="live-indicator">
            <i />
            SOC engine active
          </span>
        </div>

        <label className="field-label" htmlFor="target">
          Target domain or IP address
        </label>

        <div className="target-input-wrap">
          <span>https://</span>
          <input
            id="target"
            value={target}
            onChange={(event: ChangeEvent<HTMLInputElement>) => setTarget(event.target.value)}
            placeholder="example.com"
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        <label className="auth-check">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
          />
          <span className="check-box">
            <ShieldIcon />
          </span>
          <span>I confirm that I am authorized to scan this target.</span>
        </label>

        {error && <div className="error-banner mb-4">{error}</div>}

        <button
          type="submit"
          className="primary-button"
          disabled={!authorized || !target.trim() || submitting}
        >
          <PlayIcon />
          {submitting ? "Launching pipeline..." : "Run discovery scan"}
        </button>
      </form>

      {/* Standalone Security Modules */}
      <SecurityModules />

      {/* Operational analytics dashboard — real scan + findings data only */}
      {!loading && <DashboardAnalytics scans={scans} />}

      {/* Scans list */}
      <section id="scans" className="history-section-panel mt-6">
        <div className="section-heading mb-4">
          <div>
            <small>Assigned audits</small>
            <h2>Security Assessment History</h2>
          </div>
          <span>{scans.length} scans run</span>
        </div>

        {loading ? (
          <div className="empty-state">
            <div className="loader" />
            Loading scan database...
          </div>
        ) : scans.length ? (
          <div className="space-y-3" style={{ display: "grid", gap: "12px" }}>
            {scans.map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <RadarIcon />
            <h3>No assessments executed</h3>
            <p>Launch your first target discovery scan to generate logs and vulnerability findings.</p>
          </div>
        )}
      </section>
    </main>
  );
}
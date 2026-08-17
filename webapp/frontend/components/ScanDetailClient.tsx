"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, scanSocketUrl } from "@/lib/api";
import { formatDate } from "@/lib/format";
import type { Artifact, Scan, ScanLog } from "@/lib/types";
import { Header } from "./Header";
import { ArtifactViewer } from "./ArtifactViewer";
import { Pipeline } from "./Pipeline";
import { ReportDashboard } from "./ReportDashboard";
import { StatusPill } from "./StatusPill";
import {
  ChevronIcon,
  ClockIcon,
  RadarIcon,
  TerminalIcon,
  XIcon,
} from "./Icons";
import { useAuth } from "@/lib/auth";
import { useRouter } from "next/navigation";

export function ScanDetailClient({ scanId }: { scanId: string }) {
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();

  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [tab, setTab] = useState<"overview" | "intelligence">("overview");
  const [viewer, setViewer] = useState<Artifact | null>(null);
  const [error, setError] = useState("");
  const [socketState, setSocketState] = useState<
    "connecting" | "live" | "polling"
  >("connecting");

  const logEnd = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/login");
    }
  }, [user, authLoading, router]);

  const refreshArtifacts = useCallback(() => {
    return api
      .getArtifacts(scanId)
      .then(setArtifacts)
      .catch(() => undefined);
  }, [scanId]);

  const refreshScan = useCallback(() => {
    return api
      .getScan(scanId)
      .then(setScan)
      .catch((err: Error) => setError(err.message));
  }, [scanId]);

  useEffect(() => {
    if (!user) return;

    let polling: ReturnType<typeof setInterval> | undefined;

    const loadInitial = async () => {
      try {
        const [scanData, logsData, artifactsData] = await Promise.all([
          api.getScan(scanId),
          api.getLogs(scanId),
          api.getArtifacts(scanId),
        ]);

        setScan(scanData);
        setLogs(logsData);
        setArtifacts(artifactsData);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unable to load scan"
        );
      }
    };

    loadInitial();

    const socket = new WebSocket(scanSocketUrl(scanId));

    socket.onopen = () => {
      setSocketState("live");
    };

    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);

        if (event.scan) {
          setScan(event.scan);

          if (
            event.scan.status === "completed" ||
            event.scan.status === "failed"
          ) {
            refreshArtifacts();
          }
        }

        if (event.log) {
          setLogs((current) =>
            [...current, event.log].slice(-1000)
          );
        }

        if (event.logs) {
          setLogs(event.logs);
        }

      } catch {
        // Ignore malformed websocket messages
      }
    };

    socket.onerror = () => {
      socket.close();
    };

    socket.onclose = () => {
      setSocketState("polling");

      polling = setInterval(async () => {
        const currentScan = await api
          .getScan(scanId)
          .catch(() => null);

        if (currentScan) {
          setScan(currentScan);

          if (
            currentScan.status === "completed" ||
            currentScan.status === "failed"
          ) {
            if (polling) {
              clearInterval(polling);
            }
            return;
          }
        }

        setLogs((current) => {
          const lastId = current.at(-1)?.id || 0;

          api
            .getLogs(scanId, lastId)
            .then((next) => {
              if (next.length) {
                setLogs((latest) =>
                  [...latest, ...next].slice(-1000)
                );
              }
            });

          return current;
        });

      }, 5000);
    };

    return () => {
      socket.close();

      if (polling) {
        clearInterval(polling);
      }
    };

  }, [scanId, user, refreshArtifacts]);

  useEffect(() => {
    if (tab === "overview") {
      logEnd.current?.scrollIntoView({
        behavior: "smooth",
      });
    }
  }, [logs.length, tab]);

  const reportArtifactCount = useMemo(
    () => artifacts.length,
    [artifacts]
  );

  async function cancel() {
    try {
      await api.cancelScan(scanId);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to cancel scan"
      );
    }
  }

  if (authLoading || !user) {
    return (
      <main className="shell">
        <Header />
        <div className="empty-state page-loading">
          <div className="loader" />
          Authenticating...
        </div>
      </main>
    );
  }

  if (!scan) {
    return (
      <main className="shell">
        <Header />
        <div className="empty-state page-loading">
          {error || (
            <>
              <div className="loader" />
              Loading assessment...
            </>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="shell scan-shell">

      <Header target={scan.target} />

      <div className="breadcrumb">
        <Link href="/">Assessments</Link>
        <ChevronIcon />
        <span>{scan.target}</span>
      </div>

      <section className="detail-hero premium-detail-hero">
        <div>
          <div className="eyebrow">
            <span />
            Security assessment workspace
          </div>

          <h1>{scan.target}</h1>

          <div className="detail-meta">

            <StatusPill status={scan.status} />

            <span>
              <ClockIcon />
              Started {formatDate(scan.started_at)}
            </span>

            <span className={`socket-state ${socketState}`}>
              <i />
              {socketState === "live"
                ? "Live socket"
                : socketState === "polling"
                ? "Polling fallback"
                : "Connecting"}
            </span>

          </div>
        </div>

        <div className="hero-actions">

          <button
            className="secondary-button"
            onClick={() => setTab("intelligence")}
          >
            <RadarIcon />
            Open intelligence
          </button>

          {scan.status === "running" && (
            <button
              className="danger-button"
              onClick={cancel}
            >
              <XIcon />
              Cancel scan
            </button>
          )}

        </div>
      </section>


      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      {scan.error_message && (
        <div className="error-banner">
          <strong>Pipeline stopped:</strong>{" "}
          {scan.error_message}
        </div>
      )}


      <section className="pipeline-card premium-pipeline-card">

        <div className="pipeline-card-head">
          <div>
            <small>Orchestration</small>
            <h2>Pipeline progress</h2>
          </div>

          <strong>
            {scan.progress}%
          </strong>
        </div>

        <div className="main-progress">
          <span
            style={{
              width: `${scan.progress}%`,
            }}
          />
        </div>

        <Pipeline steps={scan.steps} />

      </section>


      <nav className="workspace-tabs">

        <button
          className={tab === "overview" ? "active" : ""}
          onClick={() => setTab("overview")}
        >
          <TerminalIcon />
          Live operations
        </button>


        <button
          className={tab === "intelligence" ? "active" : ""}
          onClick={() => setTab("intelligence")}
        >
          <RadarIcon />
          Security intelligence
          <b>{reportArtifactCount}</b>
        </button>

      </nav>


      {tab === "overview" && (
        <section className="overview-grid">

          <div className="terminal-card">

            <header>
              <div>
                <span className="terminal-dots">
                  <i />
                  <i />
                  <i />
                </span>

                <strong>
                  Live execution output
                </strong>
              </div>

              <small>
                {logs.length} events
              </small>
            </header>


            <div className="terminal-body">

              {logs.length ? (
                logs.map((log,index)=>(
                  <div
                    className={`log-line ${log.level}`}
                    key={`${log.id}-${log.created_at}-${index}`}
                  >

                    <time>
                      {new Date(
                        log.created_at
                      ).toLocaleTimeString()}
                    </time>

                    <span className="log-module">
                      {log.step_key || "system"}
                    </span>

                    <p>
                      {log.message}
                    </p>

                  </div>
                ))
              ) : (
                <div className="terminal-empty">
                  Waiting for scanner output...
                </div>
              )}

              <div ref={logEnd}/>

            </div>

          </div>


          <aside className="summary-stack">

            <div className="summary-card current-module">
              <small>Current module</small>

              <strong>
                {scan.current_step ||
                (scan.status === "completed"
                  ? "Completed"
                  : scan.status)}
              </strong>

              <span>
                {scan.steps.find(
                  step =>
                    step.step_key === scan.current_step
                )?.message ||
                "No active process"}
              </span>

            </div>


            <div className="summary-card metrics">

              <div>
                <small>Steps done</small>
                <strong>
                  {
                    scan.steps.filter(
                      step =>
                        step.status === "completed"
                    ).length
                  }
                </strong>
              </div>


              <div>
                <small>Artifacts</small>
                <strong>
                  {artifacts.length}
                </strong>
              </div>


              <div>
                <small>Progress</small>
                <strong>
                  {scan.progress}%
                </strong>
              </div>

            </div>


            <div className="summary-card">
              <small>
                Output directory
              </small>

              <code>
                {scan.run_dir ||
                "Created after reconnaissance starts"}
              </code>

            </div>

          </aside>

        </section>
      )}


      {tab === "intelligence" && (
        <ReportDashboard
          scan={scan}
          artifacts={artifacts}
          onOpenArtifact={setViewer}
        />
      )}


      {viewer && (
        <ArtifactViewer
          artifact={viewer}
          onClose={() => setViewer(null)}
        />
      )}

    </main>
  );
}
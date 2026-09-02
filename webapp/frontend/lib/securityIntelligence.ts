import { api } from "./api";
import type { Artifact, Scan } from "./types";
import { computeSeverityCounts, type Finding, type Severity } from "./reportParsing";

export interface IntelligenceMetrics {
  totalAssets: number | null;
  subdomains: number | null;
  urls: number | null;
  endpoints: number | null;
  technologies: number | null;
  openPorts: number | null;
  screenshots: number;
  liveAssets: number | null;
  deadAssets: number | null;
  highRiskAssets: number | null;
  suspiciousEndpoints: number | null;
}

export interface IntelligenceData {
  metrics: IntelligenceMetrics;
  severityCounts: Record<Severity, number>;
  sourceArtifacts: Artifact[];
  combinedReportArtifact: Artifact | null;
  scanId: string;
  target: string;
}

function parseJson(raw: string): any {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function artifactByName(artifacts: Artifact[], name: string): Artifact | undefined {
  return artifacts.find((artifact) => artifact.name.toLowerCase() === name.toLowerCase());
}

async function readArtifact(artifact: Artifact | undefined): Promise<string | null> {
  if (!artifact) return null;
  try {
    return await api.artifactText(artifact.id);
  } catch {
    return null;
  }
}

export async function loadSecurityIntelligence(artifacts: Artifact[], scan: Scan): Promise<IntelligenceData> {
  let metricsData: any = {};
  try {
    metricsData = await api.getMetrics(scan.id);
  } catch (e) {
    console.error("Failed to fetch metrics", e);
  }

  // Read lightweight summary artifacts as fallback / supplemental stats
  const names = {
    reconSummary: artifactByName(artifacts, "summary.json"),
    normalizationSummary: artifactByName(artifacts, "normalization_summary.json"),
    technologySummary: artifactByName(artifacts, "technology_enrichment_summary.json"),
    cveSummary: artifactByName(artifacts, "cve_summary.json"),
    combinedReport: artifactByName(artifacts, "combined_vapt_intelligence_report.md"),
  };

  const [reconText, normalizationText, technologySummaryText, cveSummaryText] = await Promise.all([
    readArtifact(names.reconSummary),
    readArtifact(names.normalizationSummary),
    readArtifact(names.technologySummary),
    readArtifact(names.cveSummary),
  ]);

  const recon = reconText ? parseJson(reconText) : null;
  const normalization = normalizationText ? parseJson(normalizationText) : null;
  const techSummary = technologySummaryText ? parseJson(technologySummaryText) : null;
  const cveSummary = cveSummaryText ? parseJson(cveSummaryText) : null;

  const reconCounts = (recon && typeof recon.counts === "object" && recon.counts) || {};
  const normCounts = (normalization && typeof normalization.counts === "object" && normalization.counts) || {};
  const techCounts = (techSummary && typeof techSummary.counts === "object" && techSummary.counts) || {};
  const cveCounts = (cveSummary && typeof cveSummary.counts === "object" && cveSummary.counts) || {};

  const screenshots = artifacts.filter((a) => a.kind === "screenshot" || a.kind === "image").length;

  const totalAssets = metricsData?.total_assets ?? metricsData?.assets_count ?? normCounts?.assets ?? null;
  const subdomains = metricsData?.subdomains_count ?? reconCounts?.validated_dns_hosts ?? reconCounts?.raw_subdomains ?? null;
  const urls = metricsData?.urls_count ?? reconCounts?.katana_urls ?? reconCounts?.raw_katana_urls_before_normalization ?? null;
  const endpoints = metricsData?.total_endpoints ?? metricsData?.endpoints_count ?? normCounts?.endpoints ?? null;
  const technologies = metricsData?.total_technologies ?? metricsData?.technologies_count ?? techCounts?.technologies ?? null;
  const openPorts = metricsData?.total_services ?? metricsData?.ports_count ?? normCounts?.confirmed_open_services ?? reconCounts?.nmap_confirmed_open_ports ?? reconCounts?.naabu_open_port_records ?? null;
  const liveAssets = metricsData?.live_assets ?? normCounts?.current_validated_assets ?? reconCounts?.http_assets_classified ?? null;
  const deadAssets = metricsData?.dead_assets ?? normCounts?.historical_unresolved_assets ?? (totalAssets !== null && liveAssets !== null ? Math.max(0, totalAssets - liveAssets) : null);

  const metrics: IntelligenceMetrics = {
    totalAssets,
    subdomains,
    urls,
    endpoints,
    technologies,
    openPorts,
    screenshots,
    liveAssets,
    deadAssets,
    highRiskAssets: 0,
    suspiciousEndpoints: normCounts?.suspicious_endpoints ?? 0,
  };

  const severityCounts: Record<Severity, number> = {
    critical: metricsData?.severity_critical ?? cveCounts?.critical ?? 0,
    high: metricsData?.severity_high ?? cveCounts?.high ?? 0,
    medium: metricsData?.severity_medium ?? cveCounts?.medium ?? 0,
    low: metricsData?.severity_low ?? cveCounts?.low ?? 0,
    info: metricsData?.severity_info ?? techCounts?.vulnerability_findings ?? cveCounts?.info ?? 0,
    unknown: metricsData?.severity_unknown ?? 0,
  };

  return {
    metrics,
    severityCounts,
    sourceArtifacts: artifacts,
    combinedReportArtifact: names.combinedReport || artifacts.find((a) => a.kind === "report" && a.name.includes("combined")) || artifacts.find((a) => a.kind === "report") || null,
    scanId: scan.id,
    target: scan.target,
  };
}

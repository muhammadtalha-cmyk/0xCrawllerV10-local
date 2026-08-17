import { api } from "./api";
import type { Artifact, Scan } from "./types";
import {
  computeSeverityCounts,
  extractFindings,
  type Finding,
  type Severity,
} from "./reportParsing";

type JsonRecord = Record<string, unknown>;

export interface AssetIntel {
  host: string;
  live: boolean | null;
  statusCode: number | null;
  title: string;
  url: string;
  priority: string;
  category: string;
  ownership: string;
  provider: string;
  technologies: string[];
  activeTestingAllowed: boolean | null;
  decision: string;
  risk: Severity | "unrated";
  addresses: string[];
}

export interface TechnologyIntel {
  name: string;
  category: string;
  version: string | null;
  confidence: string;
  confidenceScore: number | null;
  sources: string[];
  host: string;
  evidenceCount: number | null;
  serviceConfirmed: boolean;
  risk: Severity | "unrated";
}

export interface ServiceIntel {
  host: string;
  protocol: string;
  port: number | null;
  family: string;
  product: string;
  version: string;
  status: string;
  current: boolean;
}

export interface EndpointIntel {
  url: string;
  host: string;
  category: string;
  priority: string;
  state: string;
  suspicious: boolean;
}

export interface RelationshipIntel {
  source: string;
  target: string;
  relationship: string;
  current: boolean;
}

export interface CoverageIntel {
  recon: string;
  normalization: string;
  technology: string;
  report: string;
  vulnerabilityDataAvailable: boolean;
}

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

export interface ReconActivityMetric {
  label: string;
  value: number | null;
  tone: "cyan" | "blue" | "violet" | "amber";
}

export interface IntelligenceData {
  metrics: IntelligenceMetrics;
  severityCounts: Record<Severity, number>;
  findings: Finding[];
  assets: AssetIntel[];
  technologies: TechnologyIntel[];
  services: ServiceIntel[];
  endpoints: EndpointIntel[];
  relationships: RelationshipIntel[];
  coverage: CoverageIntel;
  reconActivity: ReconActivityMetric[];
  providers: Array<{ name: string; count: number }>;
  combinedReportArtifact: Artifact | null;
  sourceArtifacts: Artifact[];
  score: number | null;
  riskStatus: string;
  riskTone: "critical" | "high" | "medium" | "low" | "neutral";
  executiveSummary: string[];
  generatedAt: string | null;
}

const EMPTY_SEVERITIES: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  unknown: 0,
};

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : value === null || value === undefined ? "" : String(value);
}

function boolValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function arrayStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((item) => stringValue(item)).filter(Boolean)
    : [];
}

function getPath(record: unknown, path: string[]): unknown {
  let current = record;
  for (const key of path) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }
  return current;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function parseJson(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function severityRank(severity: Severity | "unrated"): number {
  return { critical: 6, high: 5, medium: 4, low: 3, info: 2, unknown: 1, unrated: 0 }[severity];
}

function highestSeverity(findings: Finding[]): Severity | "unrated" {
  let best: Severity | "unrated" = "unrated";
  for (const finding of findings) {
    if (severityRank(finding.severity) > severityRank(best)) best = finding.severity;
  }
  return best;
}

function normalizeHost(value: string): string {
  try {
    if (/^https?:\/\//i.test(value)) return new URL(value).hostname.toLowerCase();
  } catch {
    // Keep original fallback.
  }
  return value.replace(/^host:/, "").split("/")[0].toLowerCase();
}

function matchFindingToHost(finding: Finding, host: string): boolean {
  const normalized = normalizeHost(host);
  return normalizeHost(finding.host).includes(normalized) || normalizeHost(finding.matchedAt).includes(normalized);
}

function parseAssets(payload: unknown, findings: Finding[]): AssetIntel[] {
  return asArray(payload)
    .filter(isRecord)
    .map((item) => {
      const http = isRecord(item.http) ? item.http : {};
      const ownership = isRecord(item.ownership) ? item.ownership : {};
      const scope = isRecord(item.scope) ? item.scope : {};
      const dns = isRecord(item.dns) ? item.dns : {};
      const host = stringValue(item.host || item.asset_id).replace(/^host:/, "");
      const hostFindings = findings.filter((finding) => matchFindingToHost(finding, host));
      return {
        host,
        live: boolValue(http.live),
        statusCode: numberValue(http.status_code),
        title: stringValue(http.title),
        url: stringValue(http.primary_url),
        priority: stringValue(http.priority) || "Unrated",
        category: stringValue(http.category) || arrayStrings(item.asset_types)[0] || "Asset",
        ownership: stringValue(ownership.classification) || "unknown",
        provider: stringValue(ownership.provider) || stringValue(getPath(item, ["edge_security", "cdn", "provider"])),
        technologies: arrayStrings(item.technologies),
        activeTestingAllowed: boolValue(scope.active_testing_allowed),
        decision: stringValue(scope.decision) || "UNRATED",
        risk: highestSeverity(hostFindings),
        addresses: [...arrayStrings(dns.a), ...arrayStrings(dns.aaaa), ...arrayStrings(dns.cname)],
      };
    })
    .filter((item) => item.host);
}

function parseTechnologies(payload: unknown, findings: Finding[]): TechnologyIntel[] {
  return asArray(payload)
    .filter(isRecord)
    .map((item) => {
      const host = stringValue(item.host);
      const name = stringValue(item.name) || "Unknown technology";
      const matchingFindings = findings.filter((finding) => {
        const body = `${finding.template} ${JSON.stringify(finding.raw)}`.toLowerCase();
        return matchFindingToHost(finding, host) && body.includes(name.toLowerCase());
      });
      return {
        name,
        category: stringValue(item.category) || "Technology",
        version: item.version === null || item.version === undefined ? null : stringValue(item.version),
        confidence: stringValue(item.confidence) || "unknown",
        confidenceScore: numberValue(item.confidence_score),
        sources: arrayStrings(item.sources),
        host,
        evidenceCount: numberValue(item.evidence_count),
        serviceConfirmed: Boolean(item.service_confirmed),
        risk: highestSeverity(matchingFindings),
      };
    })
    .filter((item) => item.name);
}

function parseServices(payload: unknown): ServiceIntel[] {
  return asArray(payload)
    .filter(isRecord)
    .map((item) => ({
      host: stringValue(item.host),
      protocol: stringValue(item.protocol),
      port: numberValue(item.port),
      family: stringValue(item.service_family),
      product: stringValue(item.product),
      version: stringValue(item.version),
      status: stringValue(item.final_status),
      current: Boolean(item.current),
    }));
}

function parseEndpoints(payload: unknown): EndpointIntel[] {
  return asArray(payload)
    .filter(isRecord)
    .map((item) => ({
      url: stringValue(item.url),
      host: stringValue(item.host),
      category: stringValue(item.category) || "Endpoint",
      priority: stringValue(item.priority) || "Unrated",
      state: stringValue(item.state),
      suspicious: Boolean(item.requires_http_revalidation) || asArray(item.suspicious_reasons).length > 0,
    }));
}

function parseRelationships(payload: unknown): RelationshipIntel[] {
  return asArray(payload)
    .filter(isRecord)
    .map((item) => ({
      source: stringValue(item.source_asset).replace(/^host:/, ""),
      target: stringValue(item.target_asset).replace(/^host:/, ""),
      relationship: stringValue(item.relationship),
      current: item.current !== false,
    }));
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

function buildRisk(findings: Finding[], coverage: CoverageIntel): Pick<IntelligenceData, "score" | "riskStatus" | "riskTone"> {
  if (!coverage.vulnerabilityDataAvailable || coverage.technology.toUpperCase() !== "COMPLETE") {
    return { score: null, riskStatus: "Coverage incomplete", riskTone: "neutral" };
  }
  const counts = computeSeverityCounts(findings);
  const penalty = counts.critical * 30 + counts.high * 14 + counts.medium * 6 + counts.low * 2;
  const score = Math.max(0, 100 - Math.min(100, penalty));
  if (counts.critical > 0) return { score, riskStatus: "Critical risk", riskTone: "critical" };
  if (counts.high > 0) return { score, riskStatus: "High risk", riskTone: "high" };
  if (counts.medium > 0) return { score, riskStatus: "Medium risk", riskTone: "medium" };
  if (counts.low > 0) return { score, riskStatus: "Low risk", riskTone: "low" };
  return { score, riskStatus: "No confirmed findings", riskTone: "low" };
}

function buildSummary(metrics: IntelligenceMetrics, findings: Finding[], coverage: CoverageIntel, technologies: TechnologyIntel[]): string[] {
  const lines: string[] = [];
  if (metrics.totalAssets !== null) {
    lines.push(`${metrics.totalAssets.toLocaleString()} canonical assets are represented in the latest normalized inventory.`);
  }
  if (metrics.liveAssets !== null) {
    lines.push(`${metrics.liveAssets.toLocaleString()} assets responded to current HTTP validation${metrics.deadAssets ? `; ${metrics.deadAssets.toLocaleString()} did not` : ""}.`);
  }
  const severity = computeSeverityCounts(findings);
  if (findings.length) {
    lines.push(`${findings.length.toLocaleString()} vulnerability findings were indexed, including ${severity.critical} critical and ${severity.high} high severity results.`);
  } else if (coverage.vulnerabilityDataAvailable && coverage.technology.toUpperCase() === "COMPLETE") {
    lines.push("No confirmed vulnerability findings were indexed for the eligible targets in this run.");
  } else {
    lines.push("Vulnerability coverage is incomplete; zero indexed findings must not be interpreted as a clean bill of health.");
  }
  const exact = technologies.filter((technology) => technology.version).length;
  if (technologies.length) {
    lines.push(`${technologies.length.toLocaleString()} technology fingerprints were consolidated; ${exact.toLocaleString()} expose an exact version.`);
  }
  if (metrics.suspiciousEndpoints) {
    lines.push(`${metrics.suspiciousEndpoints.toLocaleString()} endpoint observations require focused HTTP revalidation before active testing.`);
  }
  return lines.slice(0, 4);
}

export async function loadSecurityIntelligence(artifacts: Artifact[], scan: Scan): Promise<IntelligenceData> {
  const names = {
    reconSummary: artifactByName(artifacts, "summary.json"),
    normalizationSummary: artifactByName(artifacts, "normalization_summary.json"),
    assets: artifactByName(artifacts, "asset_inventory.json"),
    enrichedAssets: artifactByName(artifacts, "asset_inventory_enriched.json"),
    services: artifactByName(artifacts, "service_inventory.json"),
    enrichedServices: artifactByName(artifacts, "service_inventory_enriched.json"),
    endpoints: artifactByName(artifacts, "endpoint_inventory.json"),
    relationships: artifactByName(artifacts, "asset_relationships.json"),
    technologySummary: artifactByName(artifacts, "technology_enrichment_summary.json"),
    technologies: artifactByName(artifacts, "technology_inventory.json"),
    findings: artifactByName(artifacts, "vulnerability_findings.json"),
    combinedReport: artifactByName(artifacts, "combined_vapt_intelligence_report.md"),
  };

  const [
    reconText,
    normalizationText,
    assetsText,
    enrichedAssetsText,
    servicesText,
    enrichedServicesText,
    endpointsText,
    relationshipsText,
    technologySummaryText,
    technologiesText,
    findingsText,
  ] = await Promise.all([
    readArtifact(names.reconSummary),
    readArtifact(names.normalizationSummary),
    readArtifact(names.assets),
    readArtifact(names.enrichedAssets),
    readArtifact(names.services),
    readArtifact(names.enrichedServices),
    readArtifact(names.endpoints),
    readArtifact(names.relationships),
    readArtifact(names.technologySummary),
    readArtifact(names.technologies),
    readArtifact(names.findings),
  ]);

  const recon = reconText ? parseJson(reconText) : null;
  const normalization = normalizationText ? parseJson(normalizationText) : null;
  const technologySummary = technologySummaryText ? parseJson(technologySummaryText) : null;
  const findingPayload = findingsText ? parseJson(findingsText) : null;
  const findings = (findingPayload ? extractFindings(findingPayload) : null) || [];
  const assetPayload = parseJson(enrichedAssetsText || assetsText || "[]");
  const servicePayload = parseJson(enrichedServicesText || servicesText || "[]");
  const endpointPayload = parseJson(endpointsText || "[]");
  const relationshipPayload = parseJson(relationshipsText || "[]");
  const technologyPayload = parseJson(technologiesText || "[]");

  const assets = parseAssets(assetPayload, findings);
  const services = parseServices(servicePayload);
  const endpoints = parseEndpoints(endpointPayload);
  const relationships = parseRelationships(relationshipPayload);
  const technologies = parseTechnologies(technologyPayload, findings);

  const reconCounts = isRecord(getPath(recon, ["counts"])) ? (getPath(recon, ["counts"]) as JsonRecord) : {};
  const normalizationCounts = isRecord(getPath(normalization, ["counts"])) ? (getPath(normalization, ["counts"]) as JsonRecord) : {};
  const technologyCounts = isRecord(getPath(technologySummary, ["counts"])) ? (getPath(technologySummary, ["counts"]) as JsonRecord) : {};
  const techStatus = stringValue(getPath(technologySummary, ["status"])) || (scan.steps.find((step) => step.step_key === "technology")?.status ?? "UNKNOWN");

  const screenshots = artifacts.filter((artifact) => artifact.kind === "screenshot" || artifact.kind === "image").length;
  const totalAssets = numberValue(normalizationCounts.assets) ?? (assets.length || null);
  const liveAssets = assets.length ? assets.filter((asset) => asset.live === true).length : numberValue(reconCounts.http_assets_classified);
  const deadAssets = assets.length && liveAssets !== null ? Math.max(0, assets.length - liveAssets) : null;
  const subdomains = numberValue(reconCounts.validated_dns_hosts) ?? numberValue(reconCounts.raw_subdomains);
  const urls = numberValue(reconCounts.katana_urls) ?? numberValue(reconCounts.raw_katana_urls_before_normalization);
  const endpointCount = numberValue(normalizationCounts.endpoints) ?? (endpoints.length || null);
  const technologyCount = numberValue(technologyCounts.technologies) ?? (technologies.length || null);
  const openPortsFromRecon = numberValue(reconCounts.nmap_confirmed_open_ports) ?? numberValue(reconCounts.naabu_open_port_records);
  const currentPorts = new Set(services.filter((service) => service.current && service.port).map((service) => `${service.host}:${service.port}`));
  const openPorts = openPortsFromRecon ?? (currentPorts.size || null);
  const highRiskHosts = new Set(findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").map((finding) => normalizeHost(finding.host)));
  const highRiskAssets = assets.length ? assets.filter((asset) => [...highRiskHosts].some((host) => host.includes(asset.host) || asset.host.includes(host))).length : null;
  const suspiciousEndpoints = numberValue(normalizationCounts.suspicious_endpoints) ?? (endpoints.length ? endpoints.filter((endpoint) => endpoint.suspicious).length : null);

  const coverage: CoverageIntel = {
    recon: stringValue(getPath(recon, ["overall_status"])) || (scan.steps.find((step) => step.step_key === "recon")?.status ?? "UNKNOWN"),
    normalization: normalization ? "COMPLETE" : (scan.steps.find((step) => step.step_key === "normalization")?.status ?? "UNKNOWN"),
    technology: techStatus || "UNKNOWN",
    report: names.combinedReport ? "COMPLETE" : (scan.steps.find((step) => step.step_key === "report")?.status ?? "UNKNOWN"),
    vulnerabilityDataAvailable: Boolean(names.findings),
  };

  const metrics: IntelligenceMetrics = {
    totalAssets,
    subdomains,
    urls,
    endpoints: endpointCount,
    technologies: technologyCount,
    openPorts,
    screenshots,
    liveAssets,
    deadAssets,
    highRiskAssets,
    suspiciousEndpoints,
  };

  const providers = new Map<string, number>();
  for (const asset of assets) {
    const provider = asset.provider || (asset.ownership.includes("third_party") ? "Third-party SaaS" : "First-party / unknown");
    providers.set(provider, (providers.get(provider) || 0) + 1);
  }

  const reconActivity: ReconActivityMetric[] = [
    { label: "DNS discoveries", value: subdomains, tone: "cyan" },
    { label: "HTTP assets", value: liveAssets, tone: "blue" },
    { label: "Crawled URLs", value: urls, tone: "violet" },
    { label: "Screenshots", value: screenshots, tone: "amber" },
  ];

  const risk = buildRisk(findings, coverage);
  const generatedAt = stringValue(getPath(technologySummary, ["generated_at"])) || stringValue(getPath(recon, ["created_at"])) || scan.completed_at || scan.started_at;

  return {
    metrics,
    severityCounts: findings.length ? computeSeverityCounts(findings) : { ...EMPTY_SEVERITIES },
    findings,
    assets,
    technologies,
    services,
    endpoints,
    relationships,
    coverage,
    reconActivity,
    providers: [...providers.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    combinedReportArtifact: names.combinedReport || null,
    sourceArtifacts: artifacts,
    ...risk,
    executiveSummary: buildSummary(metrics, findings, coverage, technologies),
    generatedAt: generatedAt || null,
  };
}

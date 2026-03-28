"use client";

import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import type { PackageResult } from "./PackageCard";
import { SEVERITY_CONFIG } from "./PackageCard";

interface AuditSummary {
  audit_id: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
  error: number;
}

type SeverityBucket =
  | "total"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "safe"
  | "error";

function KpiButton({
  label,
  value,
  accent,
  selected,
  onClick,
}: {
  label: string;
  value: number;
  accent: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      className={`w-full rounded-2xl border px-4 py-3 text-left transition ${accent} ${
        selected
          ? "border-white/35 bg-white/10 ring-2 ring-white/25"
          : "border-white/10 bg-white/4 hover:border-white/20 hover:bg-white/[0.07]"
      }`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wider text-white/45">
        {label}
      </p>
      <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-white">
        {value}
      </p>
    </button>
  );
}

function packagesInBucket(
  packages: PackageResult[],
  bucket: SeverityBucket
): PackageResult[] {
  switch (bucket) {
    case "total":
      return [...packages];
    case "critical":
      return packages.filter(
        (p) => p.status === "complete" && p.severity === "critical"
      );
    case "high":
      return packages.filter(
        (p) => p.status === "complete" && p.severity === "high"
      );
    case "medium":
      return packages.filter(
        (p) => p.status === "complete" && p.severity === "medium"
      );
    case "low":
      return packages.filter(
        (p) => p.status === "complete" && p.severity === "low"
      );
    case "safe":
      return packages.filter(
        (p) => p.status === "complete" && p.severity === "safe"
      );
    case "error":
      return packages.filter((p) => p.status === "error");
    default:
      return [];
  }
}

function bucketTitle(bucket: SeverityBucket): string {
  switch (bucket) {
    case "total":
      return "All packages in this audit";
    case "critical":
      return "Critical severity";
    case "high":
      return "High severity";
    case "medium":
      return "Medium severity";
    case "low":
      return "Low severity";
    case "safe":
      return "Safe — no suspicious signals";
    case "error":
      return "Sandbox run errors";
    default:
      return "";
  }
}

function needsAttention(pkg: PackageResult): boolean {
  if (pkg.status === "error") return true;
  if (pkg.status === "complete" && pkg.severity && pkg.severity !== "safe")
    return true;
  return false;
}

export default function AuditResultsDashboard({
  auditId,
  packages,
  summary,
  onSelectPackage,
  onDownloadSafe,
}: {
  auditId: string;
  packages: PackageResult[];
  summary: AuditSummary;
  onSelectPackage: (pkg: PackageResult) => void;
  onDownloadSafe: () => void;
}) {
  const apiUrl =
    typeof window !== "undefined"
      ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
      : "http://localhost:8000";

  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(true);
  const [aiError, setAiError] = useState<string | null>(null);
  const [activeBucket, setActiveBucket] = useState<SeverityBucket | null>(null);

  async function loadSummary() {
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await fetch(`${apiUrl}/api/v1/audit/${auditId}/ai-summary`);
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      const j = (await res.json()) as { summary: string };
      setAiSummary(j.summary);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : "Could not load summary");
    } finally {
      setAiLoading(false);
    }
  }

  useEffect(() => {
    loadSummary();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditId]);

  const attention = packages.filter(needsAttention).sort((a, b) => {
    const order: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      safe: 4,
    };
    const sa = a.status === "error" ? -1 : order[a.severity ?? "safe"] ?? 5;
    const sb = b.status === "error" ? -1 : order[b.severity ?? "safe"] ?? 5;
    if (sa !== sb) return sa - sb;
    return b.triage_score - a.triage_score;
  });

  const safeList = packages.filter(
    (p) => p.status === "complete" && p.severity === "safe"
  );

  const showDownload =
    summary.critical > 0 || summary.high > 0;

  const filtered = activeBucket
    ? packagesInBucket(packages, activeBucket)
    : [];
  const sortedFiltered =
    activeBucket === "total"
      ? filtered.sort((a, b) => {
          const order: Record<string, number> = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            safe: 4,
          };
          const sa =
            a.status === "error"
              ? -1
              : order[a.severity ?? "safe"] ?? 5;
          const sb =
            b.status === "error"
              ? -1
              : order[b.severity ?? "safe"] ?? 5;
          if (sa !== sb) return sa - sb;
          return b.triage_score - a.triage_score;
        })
      : filtered;

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-white">Audit dashboard</h2>
        <p className="mt-1 text-sm text-white/50">
          Tap a category to see only those packages. &quot;Run errors&quot; are
          failed sandboxes, not severity ratings.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <KpiButton
          label="Total audits"
          value={summary.total}
          accent=""
          selected={activeBucket === "total"}
          onClick={() => setActiveBucket("total")}
        />
        <KpiButton
          label="Critical"
          value={summary.critical}
          accent="ring-1 ring-red-500/30"
          selected={activeBucket === "critical"}
          onClick={() => setActiveBucket("critical")}
        />
        <KpiButton
          label="High"
          value={summary.high}
          accent="ring-1 ring-orange-500/25"
          selected={activeBucket === "high"}
          onClick={() => setActiveBucket("high")}
        />
        <KpiButton
          label="Medium"
          value={summary.medium}
          accent="ring-1 ring-yellow-500/20"
          selected={activeBucket === "medium"}
          onClick={() => setActiveBucket("medium")}
        />
        <KpiButton
          label="Low"
          value={summary.low}
          accent=""
          selected={activeBucket === "low"}
          onClick={() => setActiveBucket("low")}
        />
        <KpiButton
          label="Safe"
          value={summary.safe}
          accent="ring-1 ring-emerald-500/20"
          selected={activeBucket === "safe"}
          onClick={() => setActiveBucket("safe")}
        />
        <KpiButton
          label="Run errors"
          value={summary.error}
          accent=""
          selected={activeBucket === "error"}
          onClick={() => setActiveBucket("error")}
        />
      </div>

      {activeBucket !== null && (
        <section className="rounded-3xl border border-white/12 bg-white/5 p-5 backdrop-blur-md">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-white">
                {bucketTitle(activeBucket)}{" "}
                <span className="font-mono text-white/50">
                  ({sortedFiltered.length})
                </span>
              </h3>
              <p className="mt-1 text-xs text-white/45">
                {activeBucket === "error"
                  ? "These packages failed during install or harness execution in the sandbox."
                  : activeBucket === "total"
                    ? "Every dependency from this audit run."
                    : "Packages scored at this severity after sandbox + AI analysis."}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setActiveBucket(null)}
              className="shrink-0 rounded-xl border border-white/15 bg-white/10 px-4 py-2 text-sm font-medium text-white transition hover:bg-white/16"
            >
              Clear filter
            </button>
          </div>
          {sortedFiltered.length === 0 ? (
            <p className="mt-4 text-sm text-white/45">No packages in this category.</p>
          ) : (
            <ul className="mt-4 space-y-3">
              {sortedFiltered.map((pkg) => {
                const cfg =
                  pkg.severity && pkg.status === "complete"
                    ? SEVERITY_CONFIG[pkg.severity]
                    : null;
                return (
                  <li
                    key={pkg.package}
                    className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-black/30 p-4 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono font-semibold text-white break-all">
                          {pkg.package}
                        </span>
                        {cfg && (
                          <span
                            className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-bold ${cfg.badge}`}
                          >
                            {cfg.icon} {cfg.label}
                          </span>
                        )}
                        {pkg.status === "error" && (
                          <span className="rounded-full bg-white/12 px-2 py-0.5 text-[11px] font-semibold text-white/75">
                            Run error
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-xs text-white/40">{pkg.version}</p>
                      {pkg.status === "error" && pkg.error && (
                        <pre className="mt-2 max-h-24 overflow-auto rounded-lg bg-black/40 p-2 font-mono text-xs text-red-300/90">
                          {pkg.error}
                        </pre>
                      )}
                      {pkg.summary && pkg.status === "complete" && (
                        <p className="mt-2 text-sm text-white/65 line-clamp-3">
                          {pkg.summary}
                        </p>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => onSelectPackage(pkg)}
                      className="shrink-0 rounded-xl bg-white px-5 py-2.5 text-sm font-semibold text-black transition hover:bg-white/90"
                    >
                      View full analysis
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}

      <section className="rounded-3xl border border-white/12 bg-white/[0.05] p-5 backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-white">AI executive summary</h3>
          <button
            type="button"
            onClick={loadSummary}
            disabled={aiLoading}
            className="rounded-xl border border-white/15 bg-white/10 px-4 py-2 text-sm font-medium text-white transition hover:bg-white/16 disabled:opacity-50"
          >
            {aiLoading ? "Generating…" : "Refresh summary"}
          </button>
        </div>
        {aiLoading && (
          <p className="mt-4 text-sm text-white/45">Synthesizing audit overview…</p>
        )}
        {aiError && (
          <p className="mt-4 text-sm text-red-400/90">{aiError}</p>
        )}
        {!aiLoading && !aiError && aiSummary && (
          <div className="mt-4 text-sm leading-relaxed text-white/78">
            <ReactMarkdown
              components={{
                h1: (p) => <h1 className="text-base font-bold text-white mb-2 mt-4" {...p} />,
                h2: (p) => <h2 className="text-sm font-semibold text-white mb-1 mt-3" {...p} />,
                h3: (p) => <h3 className="text-sm font-semibold text-white/90 mb-1 mt-2" {...p} />,
                strong: (p) => <strong className="font-semibold text-white" {...p} />,
                p: (p) => <p className="mb-2" {...p} />,
                ul: (p) => <ul className="list-disc list-inside mb-2 space-y-1" {...p} />,
                li: (p) => <li className="ml-2" {...p} />,
                hr: () => <hr className="border-white/10 my-3" />,
              }}
            >
              {aiSummary}
            </ReactMarkdown>
          </div>
        )}
      </section>

      {showDownload && (
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={onDownloadSafe}
            className="rounded-2xl border border-emerald-500/35 bg-emerald-500/15 px-5 py-3 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/25"
          >
            Download cleaned package.json
          </button>
        </div>
      )}

      {activeBucket === null && (
      <section>
        <h3 className="mb-3 text-sm font-semibold text-white">
          Needs attention ({attention.length})
        </h3>
        {attention.length === 0 ? (
          <p className="rounded-2xl border border-emerald-500/25 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-100/90">
            No elevated risks or sandbox errors. Review safe packages below if you want full telemetry.
          </p>
        ) : (
          <ul className="space-y-3">
            {attention.map((pkg) => {
              const cfg =
                pkg.severity && pkg.status === "complete"
                  ? SEVERITY_CONFIG[pkg.severity]
                  : null;
              return (
                <li
                  key={pkg.package}
                  className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-black/30 p-4 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-semibold text-white break-all">
                        {pkg.package}
                      </span>
                      {cfg && (
                        <span
                          className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-bold ${cfg.badge}`}
                        >
                          {cfg.icon} {cfg.label}
                        </span>
                      )}
                      {pkg.status === "error" && (
                        <span className="rounded-full bg-white/12 px-2 py-0.5 text-[11px] font-semibold text-white/75">
                          Error
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-white/40">{pkg.version}</p>
                    {pkg.summary && (
                      <p className="mt-2 text-sm text-white/65 line-clamp-2">
                        {pkg.summary}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => onSelectPackage(pkg)}
                    className="shrink-0 rounded-xl bg-white px-5 py-2.5 text-sm font-semibold text-black transition hover:bg-white/90"
                  >
                    View full analysis
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      )}

      {activeBucket === null && (
      <section>
        <h3 className="mb-3 text-sm font-semibold text-white">
          Clean ({safeList.length})
        </h3>
        <ul className="divide-y divide-white/10 rounded-2xl border border-white/10 bg-black/20">
          {safeList.map((pkg) => (
            <li
              key={pkg.package}
              className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div>
                <span className="font-mono text-sm text-white/85">
                  {pkg.package}
                </span>
                <span className="ml-2 text-xs text-white/35">{pkg.version}</span>
              </div>
              <button
                type="button"
                onClick={() => onSelectPackage(pkg)}
                className="self-start rounded-lg border border-white/15 bg-white/8 px-4 py-1.5 text-xs font-medium text-white/85 hover:bg-white/12 sm:self-auto"
              >
                Details
              </button>
            </li>
          ))}
        </ul>
      </section>
      )}
    </div>
  );
}

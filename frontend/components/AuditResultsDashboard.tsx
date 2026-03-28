"use client";

import { useEffect, useState } from "react";
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

function Kpi({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: string;
}) {
  return (
    <div
      className={`rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 ${accent}`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wider text-white/45">
        {label}
      </p>
      <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-white">
        {value}
      </p>
    </div>
  );
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

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-white">Audit dashboard</h2>
        <p className="mt-1 text-sm text-white/50">
          Open any row for full AI analysis, runtime metrics, and registry context.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Kpi label="Total" value={summary.total} accent="" />
        <Kpi
          label="Critical"
          value={summary.critical}
          accent="ring-1 ring-red-500/30"
        />
        <Kpi
          label="High"
          value={summary.high}
          accent="ring-1 ring-orange-500/25"
        />
        <Kpi
          label="Medium"
          value={summary.medium}
          accent="ring-1 ring-yellow-500/20"
        />
        <Kpi label="Low" value={summary.low} accent="" />
        <Kpi
          label="Safe"
          value={summary.safe}
          accent="ring-1 ring-emerald-500/20"
        />
        <Kpi label="Errors" value={summary.error} accent="" />
      </div>

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
          <div className="mt-4 text-sm leading-relaxed text-white/78 whitespace-pre-wrap">
            {aiSummary}
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
    </div>
  );
}

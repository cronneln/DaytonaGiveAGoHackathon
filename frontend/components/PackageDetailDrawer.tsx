"use client";

import { useEffect } from "react";
import type { PackageResult } from "./PackageCard";
import { SEVERITY_CONFIG } from "./PackageCard";

function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | number;
  hint?: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wider text-white/45">
        {label}
      </p>
      <p className="mt-1 font-mono text-lg font-semibold text-white">{value}</p>
      {hint && (
        <p className="mt-0.5 text-xs text-white/40">{hint}</p>
      )}
    </div>
  );
}

export default function PackageDetailDrawer({
  pkg,
  onClose,
}: {
  pkg: PackageResult | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!pkg) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [pkg, onClose]);

  if (!pkg) return null;

  const cfg = pkg.severity ? SEVERITY_CONFIG[pkg.severity] : null;
  const rt = pkg.runtime;
  const cpuPct = Math.round((rt?.cpuUserRatioMax ?? 0) * 100);
  const cpuBar = Math.min(100, cpuPct);
  const netCount = rt?.networkCalls?.length ?? 0;
  const writes = rt?.fileSystemWrites?.length ?? 0;
  const sensReads = rt?.fileSystemReads?.filter((r) => r.suspicious).length ?? 0;
  const envCount = rt?.envVarAccess?.length ?? 0;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close panel"
        className="absolute inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />
      <aside
        className="relative flex h-full w-full max-w-lg flex-col border-l border-white/12 bg-[#0a0a0a] shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pkg-detail-title"
      >
        <div className="flex items-start justify-between gap-3 border-b border-white/10 px-5 py-4">
          <div className="min-w-0">
            <h2
              id="pkg-detail-title"
              className="font-mono text-lg font-semibold text-white break-all"
            >
              {pkg.package}
            </h2>
            <p className="text-sm text-white/45">{pkg.version}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {cfg && (
                <span
                  className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold ${cfg.badge}`}
                >
                  {cfg.icon} {cfg.label}
                </span>
              )}
              {pkg.status === "error" && (
                <span className="rounded-full bg-white/12 px-2.5 py-0.5 text-xs font-semibold text-white/80">
                  Sandbox error
                </span>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 rounded-xl border border-white/15 bg-white/8 px-4 py-2 text-sm font-medium text-white transition hover:bg-white/14"
          >
            Close
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6">
          {pkg.summary && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                Summary
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-white/85">{pkg.summary}</p>
            </section>
          )}

          {pkg.status === "complete" && rt && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                Runtime metrics
              </h3>
              <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
                <StatCard label="Network calls" value={netCount} />
                <StatCard label="File writes" value={writes} />
                <StatCard label="Sensitive reads" value={sensReads} />
                <StatCard label="Env probes" value={envCount} />
                <StatCard
                  label="CPU (user share)"
                  value={`${cpuPct}%`}
                  hint={
                    rt.cpuAnomaly
                      ? "Spike detected — possible miner"
                      : "Across cores, install window"
                  }
                />
              </div>
              <div className="mt-4">
                <div className="mb-1 flex justify-between text-xs text-white/50">
                  <span>CPU profile</span>
                  <span>{cpuPct}%</span>
                </div>
                <div className="h-2.5 overflow-hidden rounded-full bg-white/10">
                  <div
                    className={`h-full rounded-full transition-all ${
                      rt.cpuAnomaly ? "bg-amber-500" : "bg-emerald-500/90"
                    }`}
                    style={{ width: `${cpuBar}%` }}
                  />
                </div>
              </div>
            </section>
          )}

          {pkg.explanation && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                AI analysis
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-white/80 whitespace-pre-wrap">
                {pkg.explanation}
              </p>
            </section>
          )}

          {pkg.behaviors.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                Behaviors flagged
              </h3>
              <ul className="mt-2 space-y-2">
                {pkg.behaviors.map((b, i) => (
                  <li key={i} className="flex gap-2 text-sm text-white/78">
                    <span className="text-amber-400/90">•</span>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {pkg.triage_reasons.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                Registry signals
                <span className="ml-2 font-mono text-white/35">
                  (score {pkg.triage_score})
                </span>
              </h3>
              <ul className="mt-2 space-y-1.5">
                {pkg.triage_reasons.map((r, i) => (
                  <li key={i} className="text-sm text-white/55">
                    — {r}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {pkg.status === "error" && pkg.error && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-red-400/80">
                Error
              </h3>
              <pre className="mt-2 overflow-x-auto rounded-xl bg-black/50 p-3 font-mono text-xs text-white/65">
                {pkg.error}
              </pre>
            </section>
          )}

          {pkg.status === "complete" && rt && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-white/45">
                Raw runtime
              </h3>
              <pre className="mt-2 max-h-48 overflow-auto rounded-xl bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-white/50">
                {JSON.stringify(rt, null, 2)}
              </pre>
            </section>
          )}
        </div>
      </aside>
    </div>
  );
}

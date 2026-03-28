"use client";

import { useState } from "react";

export type Severity = "critical" | "high" | "medium" | "low" | "safe";

export interface PackageResult {
  package: string;
  version: string;
  triage_score: number;
  triage_reasons: string[];
  severity: Severity | null;
  behaviors: string[];
  summary: string;
  explanation: string;
  status: "queued" | "running" | "complete" | "error";
  error?: string;
  runtime?: {
    networkCalls: Array<{ protocol: string; host: string; port?: number; path?: string }>;
    fileSystemWrites: Array<{ path: string }>;
    fileSystemReads: Array<{ path: string; suspicious: boolean }>;
    envVarAccess: Array<{ key: string }>;
    cpuAnomaly: boolean;
    errors: string[];
  };
}

const SEVERITY_CONFIG = {
  critical: {
    bg: "bg-red-950",
    border: "border-red-700",
    badge: "bg-red-600 text-white",
    dot: "bg-red-500",
    label: "CRITICAL",
    icon: "💀",
  },
  high: {
    bg: "bg-orange-950",
    border: "border-orange-700",
    badge: "bg-orange-600 text-white",
    dot: "bg-orange-500",
    label: "HIGH",
    icon: "⚠️",
  },
  medium: {
    bg: "bg-yellow-950",
    border: "border-yellow-700",
    badge: "bg-yellow-600 text-white",
    dot: "bg-yellow-500",
    label: "MEDIUM",
    icon: "🔶",
  },
  low: {
    bg: "bg-blue-950",
    border: "border-blue-800",
    badge: "bg-blue-700 text-white",
    dot: "bg-blue-400",
    label: "LOW",
    icon: "ℹ️",
  },
  safe: {
    bg: "bg-green-950",
    border: "border-green-800",
    badge: "bg-green-700 text-white",
    dot: "bg-green-500",
    label: "SAFE",
    icon: "✅",
  },
};

export default function PackageCard({ pkg }: { pkg: PackageResult }) {
  const [expanded, setExpanded] = useState(false);
  const isRunning = pkg.status === "running" || pkg.status === "queued";
  const isError = pkg.status === "error";

  const cfg = pkg.severity ? SEVERITY_CONFIG[pkg.severity] : null;

  return (
    <div
      className={`rounded-xl border p-4 transition-all duration-300 ${
        cfg ? `${cfg.bg} ${cfg.border}` : "bg-gray-900 border-gray-700"
      }`}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          {/* Status dot */}
          {isRunning ? (
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse flex-shrink-0" />
          ) : cfg ? (
            <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
          ) : (
            <span className="w-2.5 h-2.5 rounded-full bg-gray-600 flex-shrink-0" />
          )}

          <div className="min-w-0">
            <span className="font-mono font-semibold text-white truncate block">
              {pkg.package}
            </span>
            <span className="text-xs text-gray-500">{pkg.version}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {isRunning && (
            <span className="text-xs text-blue-400 flex items-center gap-1">
              <span className="animate-spin inline-block">⟳</span>
              {pkg.status === "queued" ? "Queued" : "Running sandbox…"}
            </span>
          )}
          {isError && (
            <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">
              Error
            </span>
          )}
          {cfg && (
            <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${cfg.badge}`}>
              {cfg.icon} {cfg.label}
            </span>
          )}
        </div>
      </div>

      {/* Summary */}
      {pkg.summary && (
        <p className="mt-3 text-sm text-gray-300">{pkg.summary}</p>
      )}

      {/* Behaviors */}
      {pkg.behaviors.length > 0 && (
        <ul className="mt-3 space-y-1">
          {pkg.behaviors.map((b, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span className="text-red-400 mt-0.5 flex-shrink-0">•</span>
              <span className="text-gray-300">{b}</span>
            </li>
          ))}
        </ul>
      )}

      {/* Error */}
      {isError && pkg.error && (
        <p className="mt-3 text-sm text-gray-400 font-mono bg-gray-800 rounded px-3 py-2">
          {pkg.error}
        </p>
      )}

      {/* Expand button */}
      {pkg.status === "complete" && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="mt-3 text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          {expanded ? "▲ Hide details" : "▼ Show details"}
        </button>
      )}

      {/* Expanded: triage + runtime logs */}
      {expanded && pkg.status === "complete" && (
        <div className="mt-3 space-y-3 border-t border-gray-700 pt-3">
          {/* Explanation */}
          {pkg.explanation && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">
                Analysis
              </p>
              <p className="text-sm text-gray-300">{pkg.explanation}</p>
            </div>
          )}

          {/* Triage reasons */}
          {pkg.triage_reasons.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">
                Registry Flags (score: {pkg.triage_score})
              </p>
              <ul className="space-y-0.5">
                {pkg.triage_reasons.map((r, i) => (
                  <li key={i} className="text-xs text-gray-400">
                    — {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Runtime report */}
          {pkg.runtime && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">
                Runtime Report
              </p>
              <div className="bg-gray-900 rounded-lg p-3 font-mono text-xs text-gray-400 space-y-1 overflow-x-auto">
                <p>
                  Network calls:{" "}
                  {pkg.runtime.networkCalls.length > 0
                    ? pkg.runtime.networkCalls
                        .map((c) => `${c.protocol}://${c.host}`)
                        .join(", ")
                    : "none"}
                </p>
                <p>FS writes: {pkg.runtime.fileSystemWrites.length}</p>
                <p>
                  Sensitive reads:{" "}
                  {pkg.runtime.fileSystemReads
                    .filter((r) => r.suspicious)
                    .map((r) => r.path)
                    .join(", ") || "none"}
                </p>
                <p>
                  Env vars accessed:{" "}
                  {pkg.runtime.envVarAccess.map((e) => e.key).join(", ") ||
                    "none"}
                </p>
                <p>CPU anomaly: {pkg.runtime.cpuAnomaly ? "YES ⚠" : "no"}</p>
                {pkg.runtime.errors.length > 0 && (
                  <p>Errors: {pkg.runtime.errors.join("; ")}</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

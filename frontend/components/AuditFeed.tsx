"use client";

import { useEffect, useState, useRef } from "react";
import PackageCard, { PackageResult, Severity } from "./PackageCard";

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

interface SSEEvent {
  type: string;
  data?: PackageResult;
  message?: string;
  total?: number;
  summary?: AuditSummary;
}

export default function AuditFeed({ auditId }: { auditId: string }) {
  const [packages, setPackages] = useState<Map<string, PackageResult>>(
    new Map()
  );
  const [status, setStatus] = useState<
    "connecting" | "triaging" | "running" | "complete" | "error"
  >("connecting");
  const [statusMsg, setStatusMsg] = useState("Connecting to audit stream…");
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [totalExpected, setTotalExpected] = useState<number | null>(null);
  const esRef = useRef<EventSource | null>(null);

  const apiUrl =
    typeof window !== "undefined"
      ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
      : "http://localhost:8000";

  useEffect(() => {
    const es = new EventSource(`${apiUrl}/api/v1/audit/${auditId}/stream`);
    esRef.current = es;

    es.onmessage = (e: MessageEvent) => {
      const event = JSON.parse(e.data as string) as SSEEvent;

      if (event.type === "status") {
        setStatus("triaging");
        setStatusMsg(event.message ?? "");
      } else if (event.type === "triage_complete") {
        setStatus("running");
        setTotalExpected(event.total ?? null);
        setStatusMsg(event.message ?? "");
      } else if (event.type === "package_update" && event.data) {
        setPackages((prev) => {
          const next = new Map(prev);
          next.set(event.data!.package, event.data!);
          return next;
        });
      } else if (event.type === "package_result" && event.data) {
        setPackages((prev) => {
          const next = new Map(prev);
          next.set(event.data!.package, event.data!);
          return next;
        });
      } else if (event.type === "complete") {
        setStatus("complete");
        setSummary(event.summary ?? null);
        es.close();
      } else if (event.type === "error") {
        setStatus("error");
        setStatusMsg(event.message ?? "Unknown error");
        es.close();
      }
      // ping — ignore
    };

    es.onerror = () => {
      if (status !== "complete") {
        setStatus("error");
        setStatusMsg("Connection lost. Results may be incomplete.");
      }
    };

    return () => {
      es.close();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditId]);

  const pkgList = Array.from(packages.values()).sort((a, b) => {
    const order: Record<Severity | "null", number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      safe: 4,
      null: 5,
    };
    const sa = order[(a.severity ?? "null") as Severity | "null"];
    const sb = order[(b.severity ?? "null") as Severity | "null"];
    if (sa !== sb) return sa - sb;
    return b.triage_score - a.triage_score;
  });

  const running = pkgList.filter(
    (p) => p.status === "running" || p.status === "queued"
  ).length;
  const done = pkgList.filter((p) => p.status === "complete" || p.status === "error").length;

  async function downloadSafeJson() {
    const apiUrl2 = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    const res = await fetch(`${apiUrl2}/api/v1/audit/${auditId}/safe-package-json`);
    const data = await res.json() as { dependencies: Record<string, string>; removed: Array<{package: string; severity: string; summary: string}>; message: string };
    const blob = new Blob([JSON.stringify({ dependencies: data.dependencies }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "safe-package.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      {/* Status bar */}
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {status === "connecting" || status === "triaging" || status === "running" ? (
              <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse" />
            ) : status === "complete" ? (
              <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
            ) : (
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
            )}
            <span className="text-sm text-gray-300">{statusMsg}</span>
          </div>
          {totalExpected !== null && (
            <span className="text-xs text-gray-500">
              {done} / {totalExpected} complete
            </span>
          )}
        </div>

        {/* Progress bar */}
        {totalExpected !== null && totalExpected > 0 && (
          <div className="w-full bg-gray-800 rounded-full h-1.5">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all duration-500"
              style={{ width: `${(done / totalExpected) * 100}%` }}
            />
          </div>
        )}

        {/* Running count */}
        {running > 0 && (
          <p className="text-xs text-blue-400">
            {running} sandbox{running !== 1 ? "es" : ""} running in parallel…
          </p>
        )}
      </div>

      {/* Summary badges */}
      {summary && (
        <div className="flex flex-wrap gap-2">
          {summary.critical > 0 && (
            <span className="px-3 py-1 rounded-full text-sm font-semibold bg-red-600 text-white">
              💀 {summary.critical} Critical
            </span>
          )}
          {summary.high > 0 && (
            <span className="px-3 py-1 rounded-full text-sm font-semibold bg-orange-600 text-white">
              ⚠️ {summary.high} High
            </span>
          )}
          {summary.medium > 0 && (
            <span className="px-3 py-1 rounded-full text-sm font-semibold bg-yellow-600 text-white">
              🔶 {summary.medium} Medium
            </span>
          )}
          {summary.low > 0 && (
            <span className="px-3 py-1 rounded-full text-sm font-semibold bg-blue-700 text-white">
              ℹ️ {summary.low} Low
            </span>
          )}
          {summary.safe > 0 && (
            <span className="px-3 py-1 rounded-full text-sm font-semibold bg-green-700 text-white">
              ✅ {summary.safe} Safe
            </span>
          )}

          {(summary.critical > 0 || summary.high > 0) && (
            <button
              onClick={downloadSafeJson}
              className="ml-auto px-3 py-1 rounded-full text-sm font-semibold bg-gray-700 hover:bg-gray-600 text-white transition-colors"
            >
              ⬇ Download safe package.json
            </button>
          )}
        </div>
      )}

      {/* Package cards */}
      <div className="space-y-3">
        {pkgList.map((pkg) => (
          <PackageCard key={pkg.package} pkg={pkg} />
        ))}
        {pkgList.length === 0 && status === "connecting" && (
          <div className="text-center py-12 text-gray-600">
            <span className="animate-spin inline-block text-2xl">⟳</span>
            <p className="mt-2">Waiting for results…</p>
          </div>
        )}
      </div>
    </div>
  );
}

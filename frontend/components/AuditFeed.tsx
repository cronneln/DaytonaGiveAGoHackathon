"use client";

import { useEffect, useState } from "react";
import PackageCard, { PackageResult, Severity } from "./PackageCard";
import AuditResultsDashboard from "./AuditResultsDashboard";
import PackageDetailDrawer from "./PackageDetailDrawer";

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
  data?: PackageResult | AuditSummary;
  message?: string;
  total?: number;
}

function isAuditSummary(x: unknown): x is AuditSummary {
  return (
    typeof x === "object" &&
    x !== null &&
    "audit_id" in x &&
    typeof (x as AuditSummary).audit_id === "string"
  );
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
  const [selectedPackage, setSelectedPackage] = useState<PackageResult | null>(
    null
  );
  const apiUrl =
    typeof window !== "undefined"
      ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
      : "http://localhost:8000";

  useEffect(() => {
    const es = new EventSource(`${apiUrl}/api/v1/audit/${auditId}/stream`);

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
        if (!isAuditSummary(event.data)) {
          const pkg = event.data as PackageResult;
          setPackages((prev) => {
            const next = new Map(prev);
            next.set(pkg.package, pkg);
            return next;
          });
        }
      } else if (event.type === "package_result" && event.data) {
        if (!isAuditSummary(event.data)) {
          const pkg = event.data as PackageResult;
          setPackages((prev) => {
            const next = new Map(prev);
            next.set(pkg.package, pkg);
            return next;
          });
        }
      } else if (event.type === "complete") {
        setStatus("complete");
        const payload = event.data;
        setSummary(isAuditSummary(payload) ? payload : null);
        setStatusMsg("Audit complete");
        es.close();
      } else if (event.type === "error") {
        setStatus("error");
        setStatusMsg(event.message ?? "Unknown error");
        es.close();
      }
    };

    es.onerror = () => {
      setStatus((s) => {
        if (s !== "complete") {
          setStatusMsg("Connection lost. Results may be incomplete.");
          return "error";
        }
        return s;
      });
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
  const done = pkgList.filter(
    (p) => p.status === "complete" || p.status === "error"
  ).length;

  async function downloadSafeJson() {
    const apiUrl2 = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    const res = await fetch(
      `${apiUrl2}/api/v1/audit/${auditId}/safe-package-json`
    );
    const data = (await res.json()) as {
      dependencies: Record<string, string>;
      removed: Array<{ package: string; severity: string; summary: string }>;
      message: string;
    };
    const blob = new Blob(
      [JSON.stringify({ dependencies: data.dependencies }, null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "safe-package.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  const showDashboard = status === "complete" && summary !== null;

  return (
    <div className="space-y-6">
      {/* Status bar */}
      <div className="space-y-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 backdrop-blur-sm">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            {status === "connecting" ||
            status === "triaging" ||
            status === "running" ? (
              <span className="h-2.5 w-2.5 shrink-0 animate-pulse rounded-full bg-sky-400" />
            ) : status === "complete" ? (
              <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-emerald-500" />
            ) : (
              <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-red-500" />
            )}
            <span className="text-sm text-white/75">{statusMsg}</span>
          </div>
          {totalExpected !== null && (
            <span className="shrink-0 text-xs text-white/40">
              {done} / {totalExpected} complete
            </span>
          )}
        </div>

        {totalExpected !== null && totalExpected > 0 && !showDashboard && (
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
            <div
              className="h-1.5 rounded-full bg-sky-500 transition-all duration-500"
              style={{ width: `${(done / totalExpected) * 100}%` }}
            />
          </div>
        )}

        {running > 0 && !showDashboard && (
          <p className="text-xs text-sky-300/90">
            {running} sandbox{running !== 1 ? "es" : ""} running in parallel…
          </p>
        )}
      </div>

      {showDashboard ? (
        <>
          <AuditResultsDashboard
            auditId={auditId}
            packages={pkgList}
            summary={summary}
            onSelectPackage={setSelectedPackage}
            onDownloadSafe={downloadSafeJson}
          />
          <PackageDetailDrawer
            pkg={selectedPackage}
            onClose={() => setSelectedPackage(null)}
          />
        </>
      ) : (
        <>
          <div className="space-y-3">
            {pkgList.map((pkg) => (
              <PackageCard key={pkg.package} pkg={pkg} />
            ))}
            {pkgList.length === 0 && status === "connecting" && (
              <div className="py-12 text-center text-white/35">
                <span className="inline-block animate-spin text-2xl">⟳</span>
                <p className="mt-2">Waiting for results…</p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { PackageResult, Severity } from "./PackageCard";

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

type FilterKey = "all" | "issues" | "safe" | "running";

const SEVERITY_ORDER: Record<Severity | "null", number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  safe: 4,
  null: 5,
};

const SEVERITY_META: Record<
  Severity | "unknown",
  {
    badge: string;
    chip: string;
    border: string;
    glow: string;
    label: string;
  }
> = {
  critical: {
    badge: "bg-red-500/18 text-red-100 border border-red-400/30",
    chip: "bg-red-400",
    border: "border-red-400/22",
    glow: "shadow-[0_0_0_1px_rgba(248,113,113,0.14)]",
    label: "Critical",
  },
  high: {
    badge: "bg-orange-500/18 text-orange-100 border border-orange-400/30",
    chip: "bg-orange-300",
    border: "border-orange-400/20",
    glow: "shadow-[0_0_0_1px_rgba(251,146,60,0.12)]",
    label: "High",
  },
  medium: {
    badge: "bg-amber-500/16 text-amber-100 border border-amber-300/30",
    chip: "bg-amber-300",
    border: "border-amber-300/18",
    glow: "shadow-[0_0_0_1px_rgba(252,211,77,0.12)]",
    label: "Medium",
  },
  low: {
    badge: "bg-sky-500/16 text-sky-100 border border-sky-300/28",
    chip: "bg-sky-300",
    border: "border-sky-300/18",
    glow: "shadow-[0_0_0_1px_rgba(125,211,252,0.12)]",
    label: "Low",
  },
  safe: {
    badge: "bg-emerald-500/16 text-emerald-100 border border-emerald-300/28",
    chip: "bg-emerald-300",
    border: "border-emerald-300/18",
    glow: "shadow-[0_0_0_1px_rgba(110,231,183,0.12)]",
    label: "Safe",
  },
  unknown: {
    badge: "bg-white/8 text-white/78 border border-white/12",
    chip: "bg-white/40",
    border: "border-white/10",
    glow: "shadow-[0_0_0_1px_rgba(255,255,255,0.08)]",
    label: "Unknown",
  },
};

function classNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

function formatPaths(paths: string[]) {
  if (!paths.length) return "None observed";
  return paths.join(", ");
}

function formatHosts(pkg: PackageResult) {
  if (!pkg.runtime?.networkCalls.length) return "No outbound requests observed";

  const hosts = Array.from(
    new Set(
      pkg.runtime.networkCalls.map((call) =>
        `${call.protocol}://${call.host}${call.port ? `:${call.port}` : ""}${call.path ?? ""}`
      )
    )
  );

  return hosts.join(", ");
}

function buildAiSummary(
  pkgList: PackageResult[],
  summary: AuditSummary | null,
  status: "connecting" | "triaging" | "running" | "complete" | "error"
) {
  const risky = pkgList.filter(
    (pkg) =>
      pkg.status === "complete" &&
      pkg.severity !== null &&
      pkg.severity !== "safe"
  );
  const topIssue = risky[0];
  const cpuAlerts = pkgList.filter((pkg) => pkg.runtime?.cpuAnomaly).length;
  const envAlerts = pkgList.filter(
    (pkg) => (pkg.runtime?.envVarAccess.length ?? 0) > 0
  ).length;
  const networkAlerts = pkgList.filter(
    (pkg) => (pkg.runtime?.networkCalls.length ?? 0) > 0
  ).length;

  if (status === "connecting" || status === "triaging") {
    return {
      title: "Preparing the audit workspace",
      body:
        "We are scoring the package list and deciding which dependencies need a sandbox run before deeper analysis begins.",
      actions: [
        "Wait for the first package analyses to stream in.",
        "Use the issue list once packages start appearing.",
      ],
    };
  }

  if (!pkgList.length) {
    return {
      title: "No package results yet",
      body:
        "The dashboard will populate as soon as the first dependency reports arrive from the audit stream.",
      actions: ["Keep this page open while the sandbox workers run."],
    };
  }

  if (!risky.length && status === "complete") {
    return {
      title: "No critical or high-risk behaviors were detected",
      body:
        "The completed audit did not find any packages that escalated beyond a safe rating. You can still inspect individual packages for registry flags, runtime events, and sandbox notes.",
      actions: [
        "Review any medium or low findings before shipping.",
        "Use the detail panel to inspect packages with registry flags.",
      ],
    };
  }

  return {
    title:
      summary && summary.critical + summary.high > 0
        ? `${summary.critical + summary.high} urgent package${
            summary.critical + summary.high === 1 ? "" : "s"
          } need attention`
        : `${risky.length} package${risky.length === 1 ? "" : "s"} need review`,
    body: topIssue
      ? `${topIssue.package} is the highest-priority issue right now. ${topIssue.summary || topIssue.explanation || "Open the detail panel for the full reasoning and runtime evidence."}`
      : "Open a package from the issue list to inspect the full AI-backed explanation and runtime activity.",
    actions: [
      summary && summary.critical + summary.high > 0
        ? "Remove or quarantine critical and high-severity packages before install."
        : "Review the flagged packages in order of severity.",
      networkAlerts > 0
        ? `${networkAlerts} package${
            networkAlerts === 1 ? "" : "s"
          } made outbound network requests in the sandbox.`
        : "No outbound network activity has been observed so far.",
      envAlerts > 0
        ? `${envAlerts} package${
            envAlerts === 1 ? "" : "s"
          } accessed environment variables and should be reviewed closely.`
        : "No environment variable probing has been detected so far.",
      cpuAlerts > 0
        ? `${cpuAlerts} package${
            cpuAlerts === 1 ? "" : "s"
          } triggered the CPU anomaly signal used for cryptominer detection.`
        : "No CPU anomaly has been observed in the completed package runs.",
    ],
  };
}

function FilterButton({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean;
  label: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={classNames(
        "rounded-full border px-3 py-1.5 text-sm transition-colors",
        active
          ? "border-white/24 bg-white text-black"
          : "border-white/10 bg-white/6 text-white/62 hover:border-white/18 hover:text-white"
      )}
    >
      {label} <span className="text-xs opacity-70">{count}</span>
    </button>
  );
}

function MetricCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "default" | "danger" | "good";
}) {
  const toneClass =
    tone === "danger"
      ? "border-red-400/16 bg-red-500/10 text-red-100"
      : tone === "good"
        ? "border-emerald-400/16 bg-emerald-500/10 text-emerald-100"
        : "border-white/10 bg-white/6 text-white";

  return (
    <div className={classNames("rounded-2xl border p-4", toneClass)}>
      <p className="text-xs uppercase tracking-[0.24em] text-white/40">{label}</p>
      <p className="mt-2 text-lg font-semibold">{value}</p>
    </div>
  );
}

export default function AuditFeed({ auditId }: { auditId: string }) {
  const [packages, setPackages] = useState<Map<string, PackageResult>>(new Map());
  const [status, setStatus] = useState<
    "connecting" | "triaging" | "running" | "complete" | "error"
  >("connecting");
  const [statusMsg, setStatusMsg] = useState("Connecting to audit stream…");
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [totalExpected, setTotalExpected] = useState<number | null>(null);
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterKey>("issues");
  const esRef = useRef<EventSource | null>(null);

  const apiUrl =
    typeof window !== "undefined"
      ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
      : "http://localhost:8000";

  useEffect(() => {
    let closedByComplete = false;

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
      } else if (
        (event.type === "package_update" || event.type === "package_result") &&
        event.data
      ) {
        setPackages((prev) => {
          const next = new Map(prev);
          next.set(event.data!.package, event.data!);
          return next;
        });
      } else if (event.type === "complete") {
        closedByComplete = true;
        setStatus("complete");
        setSummary(event.summary ?? null);
        setStatusMsg("Audit complete. Select a package to inspect the full report.");
        es.close();
      } else if (event.type === "error") {
        setStatus("error");
        setStatusMsg(event.message ?? "Unknown error");
        es.close();
      }
    };

    es.onerror = () => {
      if (!closedByComplete) {
        setStatus("error");
        setStatusMsg("Connection lost. Results may be incomplete.");
      }
    };

    return () => {
      es.close();
    };
  }, [apiUrl, auditId]);

  const pkgList = useMemo(
    () =>
      Array.from(packages.values()).sort((a, b) => {
        const sa = SEVERITY_ORDER[(a.severity ?? "null") as Severity | "null"];
        const sb = SEVERITY_ORDER[(b.severity ?? "null") as Severity | "null"];
        if (sa !== sb) return sa - sb;
        return b.triage_score - a.triage_score;
      }),
    [packages]
  );

  const running = pkgList.filter(
    (pkg) => pkg.status === "running" || pkg.status === "queued"
  ).length;
  const done = pkgList.filter(
    (pkg) => pkg.status === "complete" || pkg.status === "error"
  ).length;
  const issueCount = pkgList.filter(
    (pkg) => pkg.severity && pkg.severity !== "safe"
  ).length;
  const safeCount = pkgList.filter((pkg) => pkg.severity === "safe").length;

  const filteredPackages = pkgList.filter((pkg) => {
    if (filter === "issues") return pkg.severity && pkg.severity !== "safe";
    if (filter === "safe") return pkg.severity === "safe";
    if (filter === "running") {
      return pkg.status === "queued" || pkg.status === "running";
    }
    return true;
  });

  const activePackage =
    pkgList.find((pkg) => pkg.package === selectedPackage) ??
    pkgList.find((pkg) => pkg.severity && pkg.severity !== "safe") ??
    filteredPackages[0] ??
    null;

  const aiSummary = buildAiSummary(pkgList, summary, status);

  async function downloadSafeJson() {
    const res = await fetch(`${apiUrl}/api/v1/audit/${auditId}/safe-package-json`);
    const data = (await res.json()) as {
      dependencies: Record<string, string>;
      removed: Array<{ package: string; severity: string; summary: string }>;
    };
    const blob = new Blob(
      [JSON.stringify({ dependencies: data.dependencies }, null, 2)],
      {
        type: "application/json",
      }
    );
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "safe-package.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
        <div className="rounded-[28px] border border-white/10 bg-white/6 p-5 backdrop-blur-xl">
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                  Audit status
                </p>
                <div className="mt-2 flex items-center gap-2">
                  <span
                    className={classNames(
                      "h-2.5 w-2.5 rounded-full",
                      status === "error"
                        ? "bg-red-400"
                        : status === "complete"
                          ? "bg-emerald-400"
                          : "animate-pulse bg-sky-400"
                    )}
                  />
                  <p className="text-base font-medium text-white">{statusMsg}</p>
                </div>
              </div>
              {(summary?.critical ?? 0) + (summary?.high ?? 0) > 0 && (
                <button
                  onClick={downloadSafeJson}
                  className="rounded-full border border-white/12 bg-white px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-white/92"
                >
                  Download safe package.json
                </button>
              )}
            </div>

            {totalExpected !== null && totalExpected > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm text-white/48">
                  <span>Audit progress</span>
                  <span>
                    {done} / {totalExpected} complete
                  </span>
                </div>
                <div className="h-2 rounded-full bg-white/8">
                  <div
                    className="h-2 rounded-full bg-white transition-all duration-500"
                    style={{ width: `${(done / totalExpected) * 100}%` }}
                  />
                </div>
              </div>
            )}

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <MetricCard
                label="Urgent issues"
                value={`${(summary?.critical ?? 0) + (summary?.high ?? 0)}`}
                tone={(summary?.critical ?? 0) + (summary?.high ?? 0) > 0 ? "danger" : "default"}
              />
              <MetricCard
                label="Packages reviewed"
                value={`${done}${totalExpected ? ` / ${totalExpected}` : ""}`}
              />
              <MetricCard label="Running sandboxes" value={`${running}`} />
              <MetricCard
                label="Safe packages"
                value={`${summary?.safe ?? safeCount}`}
                tone={safeCount > 0 ? "good" : "default"}
              />
            </div>
          </div>
        </div>

        <div className="rounded-[28px] border border-white/10 bg-white/6 p-5 backdrop-blur-xl">
          <p className="text-xs uppercase tracking-[0.28em] text-white/36">
            AI summary
          </p>
          <h2 className="mt-3 text-2xl font-semibold text-white">
            {aiSummary.title}
          </h2>
          <p className="mt-3 text-sm leading-7 text-white/66">{aiSummary.body}</p>
          <div className="mt-4 space-y-2">
            {aiSummary.actions.map((action) => (
              <div
                key={action}
                className="rounded-2xl border border-white/8 bg-black/18 px-4 py-3 text-sm text-white/72"
              >
                {action}
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-white/36">
            This overview is synthesized from the per-package AI explanations and runtime signals already returned by the audit pipeline.
          </p>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="rounded-[28px] border border-white/10 bg-white/6 p-4 backdrop-blur-xl">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                Findings
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">
                Package dashboard
              </h2>
            </div>
            <div className="text-sm text-white/44">{pkgList.length} packages</div>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            <FilterButton
              active={filter === "issues"}
              label="Issues"
              count={issueCount}
              onClick={() => setFilter("issues")}
            />
            <FilterButton
              active={filter === "all"}
              label="All"
              count={pkgList.length}
              onClick={() => setFilter("all")}
            />
            <FilterButton
              active={filter === "running"}
              label="Running"
              count={running}
              onClick={() => setFilter("running")}
            />
            <FilterButton
              active={filter === "safe"}
              label="Safe"
              count={safeCount}
              onClick={() => setFilter("safe")}
            />
          </div>

          <div className="mt-4 space-y-3">
            {filteredPackages.length === 0 && (
              <div className="rounded-2xl border border-white/8 bg-black/18 px-4 py-6 text-sm text-white/52">
                No packages match this filter yet.
              </div>
            )}

            {filteredPackages.map((pkg) => {
              const meta = SEVERITY_META[pkg.severity ?? "unknown"];
              const selected = activePackage?.package === pkg.package;
              const networkCount = pkg.runtime?.networkCalls.length ?? 0;
              const envCount = pkg.runtime?.envVarAccess.length ?? 0;

              return (
                <button
                  key={pkg.package}
                  onClick={() => setSelectedPackage(pkg.package)}
                  className={classNames(
                    "w-full rounded-[24px] border p-4 text-left transition-all",
                    "hover:border-white/18 hover:bg-white/8",
                    meta.border,
                    meta.glow,
                    selected
                      ? "bg-white/12 ring-1 ring-white/18"
                      : "bg-black/18"
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={classNames("h-2.5 w-2.5 rounded-full", meta.chip)} />
                        <p className="truncate font-mono text-sm font-semibold text-white">
                          {pkg.package}
                        </p>
                      </div>
                      <p className="mt-1 text-xs text-white/36">{pkg.version}</p>
                    </div>
                    <span className={classNames("rounded-full px-2.5 py-1 text-xs", meta.badge)}>
                      {meta.label}
                    </span>
                  </div>

                  <p className="mt-3 line-clamp-2 text-sm leading-6 text-white/68">
                    {pkg.summary || pkg.explanation || "Waiting for more analysis…"}
                  </p>

                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-white/44">
                    <span className="rounded-full border border-white/10 px-2.5 py-1">
                      Score {pkg.triage_score}
                    </span>
                    <span className="rounded-full border border-white/10 px-2.5 py-1">
                      Network {networkCount}
                    </span>
                    <span className="rounded-full border border-white/10 px-2.5 py-1">
                      Env {envCount}
                    </span>
                    <span className="rounded-full border border-white/10 px-2.5 py-1">
                      {pkg.status === "queued"
                        ? "Queued"
                        : pkg.status === "running"
                          ? "Running"
                          : pkg.status === "error"
                            ? "Error"
                            : "Ready"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="rounded-[28px] border border-white/10 bg-white/6 p-5 backdrop-blur-xl">
          {!activePackage ? (
            <div className="flex min-h-[520px] items-center justify-center rounded-[24px] border border-dashed border-white/10 bg-black/16 p-8 text-center text-white/48">
              Select a package from the dashboard to open the full analysis.
            </div>
          ) : (
            <div className="space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                    Selected package
                  </p>
                  <h2 className="mt-2 font-mono text-3xl font-semibold text-white">
                    {activePackage.package}
                  </h2>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span
                      className={classNames(
                        "rounded-full px-3 py-1 text-sm",
                        SEVERITY_META[activePackage.severity ?? "unknown"].badge
                      )}
                    >
                      {SEVERITY_META[activePackage.severity ?? "unknown"].label}
                    </span>
                    <span className="rounded-full border border-white/10 px-3 py-1 text-sm text-white/46">
                      Version {activePackage.version}
                    </span>
                    <span className="rounded-full border border-white/10 px-3 py-1 text-sm text-white/46">
                      Status {activePackage.status}
                    </span>
                  </div>
                </div>
                <div className="rounded-2xl border border-white/10 bg-black/18 px-4 py-3 text-sm text-white/52">
                  CPU reporting currently exposes an anomaly signal rather than a raw percentage. If the backend later emits continuous CPU telemetry, this panel can surface it directly.
                </div>
              </div>

              <div className="rounded-[24px] border border-white/10 bg-black/18 p-5">
                <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                  AI analysis
                </p>
                <p className="mt-3 text-lg font-medium text-white">
                  {activePackage.summary || "Analysis pending"}
                </p>
                <p className="mt-3 text-sm leading-7 text-white/68">
                  {activePackage.explanation ||
                    "The package is still being processed. Runtime evidence and explanation will appear here once the audit finishes."}
                </p>
              </div>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <MetricCard label="Triage score" value={`${activePackage.triage_score}`} />
                <MetricCard
                  label="Network calls"
                  value={`${activePackage.runtime?.networkCalls.length ?? 0}`}
                  tone={(activePackage.runtime?.networkCalls.length ?? 0) > 0 ? "danger" : "default"}
                />
                <MetricCard
                  label="Sensitive reads"
                  value={`${activePackage.runtime?.fileSystemReads.filter((entry) => entry.suspicious).length ?? 0}`}
                  tone={
                    (activePackage.runtime?.fileSystemReads.filter((entry) => entry.suspicious).length ?? 0) > 0
                      ? "danger"
                      : "default"
                  }
                />
                <MetricCard
                  label="FS writes"
                  value={`${activePackage.runtime?.fileSystemWrites.length ?? 0}`}
                />
                <MetricCard
                  label="Env access"
                  value={`${activePackage.runtime?.envVarAccess.length ?? 0}`}
                  tone={(activePackage.runtime?.envVarAccess.length ?? 0) > 0 ? "danger" : "default"}
                />
                <MetricCard
                  label="CPU signal"
                  value={activePackage.runtime?.cpuAnomaly ? "Anomaly detected" : "No anomaly"}
                  tone={activePackage.runtime?.cpuAnomaly ? "danger" : "good"}
                />
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-[24px] border border-white/10 bg-black/18 p-5">
                  <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                    Observed behaviors
                  </p>
                  <div className="mt-3 space-y-2">
                    {activePackage.behaviors.length > 0 ? (
                      activePackage.behaviors.map((behavior) => (
                        <div
                          key={behavior}
                          className="rounded-2xl border border-white/8 bg-white/5 px-4 py-3 text-sm text-white/72"
                        >
                          {behavior}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-white/48">
                        No notable behaviors were recorded.
                      </p>
                    )}
                  </div>
                </div>

                <div className="rounded-[24px] border border-white/10 bg-black/18 p-5">
                  <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                    Registry flags
                  </p>
                  <div className="mt-3 space-y-2">
                    {activePackage.triage_reasons.length > 0 ? (
                      activePackage.triage_reasons.map((reason) => (
                        <div
                          key={reason}
                          className="rounded-2xl border border-white/8 bg-white/5 px-4 py-3 text-sm text-white/72"
                        >
                          {reason}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-white/48">
                        No registry flags were attached to this package.
                      </p>
                    )}
                  </div>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-[24px] border border-white/10 bg-black/18 p-5">
                  <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                    Runtime evidence
                  </p>
                  <div className="mt-3 space-y-3 text-sm text-white/72">
                    <div>
                      <p className="text-white/42">Outbound destinations</p>
                      <p className="mt-1 break-words">{formatHosts(activePackage)}</p>
                    </div>
                    <div>
                      <p className="text-white/42">Filesystem writes</p>
                      <p className="mt-1 break-words">
                        {formatPaths(
                          activePackage.runtime?.fileSystemWrites.map((entry) => entry.path) ?? []
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-white/42">Sensitive reads</p>
                      <p className="mt-1 break-words">
                        {formatPaths(
                          activePackage.runtime?.fileSystemReads
                            .filter((entry) => entry.suspicious)
                            .map((entry) => entry.path) ?? []
                        )}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="rounded-[24px] border border-white/10 bg-black/18 p-5">
                  <p className="text-xs uppercase tracking-[0.28em] text-white/36">
                    Additional stats
                  </p>
                  <div className="mt-3 space-y-3 text-sm text-white/72">
                    <div>
                      <p className="text-white/42">Environment variables accessed</p>
                      <p className="mt-1 break-words">
                        {activePackage.runtime?.envVarAccess.length
                          ? activePackage.runtime.envVarAccess
                              .map((entry) => entry.key)
                              .join(", ")
                          : "None observed"}
                      </p>
                    </div>
                    <div>
                      <p className="text-white/42">CPU anomaly detector</p>
                      <p className="mt-1">
                        {activePackage.runtime?.cpuAnomaly
                          ? "Triggered. The sandbox saw a CPU spike above the anomaly threshold."
                          : "No abnormal CPU spike was reported."}
                      </p>
                    </div>
                    <div>
                      <p className="text-white/42">Errors</p>
                      <p className="mt-1 break-words">
                        {activePackage.runtime?.errors.length
                          ? activePackage.runtime.errors.join("; ")
                          : activePackage.error || "No runtime errors recorded"}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

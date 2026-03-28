"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";

const EXAMPLE = JSON.stringify(
  {
    name: "my-app",
    version: "1.0.0",
    dependencies: {
      lodash: "^4.17.21",
      express: "^4.18.2",
      axios: "^1.6.0",
      "event-stream": "3.3.6",
      chalk: "^5.3.0",
    },
    devDependencies: {
      typescript: "^5.3.0",
    },
  },
  null,
  2
);

export default function PackageInput() {
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [easterEggStage, setEasterEggStage] = useState<
    null | "colin" | "gif"
  >(null);
  const [stage2Src, setStage2Src] = useState("/easter-egg-stage2.gif");
  const [portalReady, setPortalReady] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const apiUrl =
    process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

  useEffect(() => {
    if (!easterEggStage) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prevOverflow;
    };
  }, [easterEggStage]);

  useEffect(() => {
    if (easterEggStage === "gif") {
      setStage2Src("/easter-egg-stage2.gif");
    }
  }, [easterEggStage]);

  useEffect(() => {
    setPortalReady(true);
  }, []);

  useEffect(() => {
    if (!easterEggStage) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopImmediatePropagation();
      setEasterEggStage((prev) => {
        if (prev === "colin") return "gif";
        if (prev === "gif") return null;
        return null;
      });
    }
    document.addEventListener("keydown", onKeyDown, { capture: true });
    return () =>
      document.removeEventListener("keydown", onKeyDown, { capture: true });
  }, [easterEggStage]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(value);
    } catch {
      setError("Invalid JSON — please paste a valid package.json");
      return;
    }

    const deps = Object.assign(
      {},
      parsed.dependencies,
      parsed.devDependencies
    );
    if (!Object.keys(deps).length) {
      setError('No "dependencies" or "devDependencies" found');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${apiUrl}/api/v1/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package_json: parsed }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error((d as { detail?: string }).detail ?? `Server error ${res.status}`);
      }
      const data = (await res.json()) as { audit_id: string };
      router.push(`/audit/${data.audit_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start audit");
      setLoading(false);
    }
  }

  const loadFileFromFile = useCallback((file: File) => {
    setError(null);
    const reader = new FileReader();
    reader.onload = (ev) => setValue(ev.target?.result as string);
    reader.onerror = () => setError("Could not read file");
    reader.readAsText(file);
  }, []);

  function isLikelyJsonFile(file: File): boolean {
    const name = file.name.trim().toLowerCase();
    if (name.endsWith(".json")) return true;
    const t = file.type.toLowerCase();
    return (
      t === "application/json" ||
      t === "text/json" ||
      t === "application/ld+json"
    );
  }

  function handleChosenFile(file: File) {
    if (!isLikelyJsonFile(file)) {
      setEasterEggStage("colin");
      return;
    }
    loadFileFromFile(file);
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    handleChosenFile(file);
    e.target.value = "";
  }

  function onDragEnter(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.types.includes("Files")) {
      setDragActive(true);
    }
  }

  function onDragLeave(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget as Node | null)) return;
    setDragActive(false);
  }

  function onDragOver(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.types.includes("Files")) {
      e.dataTransfer.dropEffect = "copy";
    }
  }

  function onDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    handleChosenFile(file);
  }

  const easterEggOverlay =
    portalReady &&
    easterEggStage &&
    createPortal(
      <div
        className="fixed inset-0 z-9999 h-dvh w-screen overflow-hidden bg-black"
        role="dialog"
        aria-modal="true"
        aria-label="Easter egg"
      >
        {easterEggStage === "colin" ? (
          <>
            <div className="absolute inset-0 flex items-center justify-center bg-black">
              <img
                src="/easter-egg.png"
                alt=""
                className="max-h-full max-w-full object-contain object-center"
              />
            </div>
            <p className="pointer-events-none absolute bottom-0 left-0 right-0 z-10 bg-linear-to-t from-black via-black/70 to-transparent px-6 pb-[max(2.5rem,env(safe-area-inset-bottom))] pt-24 text-center text-lg font-medium tracking-wide text-white drop-shadow-[0_2px_12px_rgba(0,0,0,0.85)] sm:text-xl">
              esc to stop looking at colin
            </p>
          </>
        ) : (
          <>
            <div className="absolute inset-0 flex items-center justify-center bg-black">
              <img
                src={stage2Src}
                alt=""
                className="max-h-full max-w-full object-contain object-center"
                onError={() => setStage2Src("/easter-egg-stage2.png")}
              />
            </div>
            <p className="pointer-events-none absolute bottom-0 left-0 right-0 z-10 bg-linear-to-t from-black via-black/70 to-transparent px-6 pb-[max(2.5rem,env(safe-area-inset-bottom))] pt-24 text-center text-lg font-medium tracking-wide text-white/90 drop-shadow-[0_2px_12px_rgba(0,0,0,0.85)] sm:text-xl">
              esc to return home
            </p>
          </>
        )}
      </div>,
      document.body
    );

  return (
    <>
      {easterEggOverlay}
      <form onSubmit={submit} className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label
            htmlFor="pkg-json"
            className="text-sm font-medium text-white/76"
          >
            Paste or drop your package.json
          </label>
          <div className="flex gap-2 text-xs">
            <button
              type="button"
              onClick={() => setValue(EXAMPLE)}
              className="text-white/56 transition-colors hover:text-white"
            >
              Load example
            </button>
            <span className="text-white/20">|</span>
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="text-white/56 transition-colors hover:text-white"
            >
              Upload or drop file
            </button>
          </div>
        </div>

        <input
          ref={fileRef}
          type="file"
          className="hidden"
          onChange={onFile}
        />

        <div
          onDragEnter={onDragEnter}
          onDragLeave={onDragLeave}
          onDragOver={onDragOver}
          onDrop={onDrop}
          className={`relative rounded-2xl transition-[box-shadow,border-color] ${
            dragActive
              ? "border-2 border-dashed border-sky-400/70 bg-sky-500/10 shadow-[0_0_0_1px_rgba(56,189,248,0.25)]"
              : "border border-transparent"
          }`}
        >
          {dragActive && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-2xl bg-black/40 backdrop-blur-[2px]">
              <p className="rounded-xl border border-white/20 bg-black/50 px-4 py-2 text-sm font-medium text-white/90">
                Drop package.json here
              </p>
            </div>
          )}
          <textarea
            id="pkg-json"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={`{\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}`}
            className={`h-64 w-full resize-none rounded-2xl border bg-black/35 p-4 font-mono text-sm text-white placeholder:text-white/24 focus:outline-none ${
              dragActive
                ? "border-sky-400/50 focus:border-sky-400/60"
                : "border-white/10 focus:border-white/24"
            }`}
            spellCheck={false}
          />
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={loading || !value.trim()}
        className="flex w-full items-center justify-center gap-2 rounded-2xl border border-white/14 bg-white px-6 py-3 font-semibold text-black transition-colors hover:bg-white/92 disabled:border-white/8 disabled:bg-white/10 disabled:text-white/30"
      >
        {loading ? (
          <>
            <span className="animate-spin inline-block">⟳</span>
            Starting audit…
          </>
        ) : (
          <>
            <span></span>
            Audit Dependencies
          </>
        )}
      </button>
    </form>
    </>
  );
}

"use client";

import { useState, useRef } from "react";
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
  const fileRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const apiUrl =
    process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

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

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setValue(ev.target?.result as string);
    reader.readAsText(file);
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label
            htmlFor="pkg-json"
            className="text-sm font-medium text-white/76"
          >
            Paste your package.json
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
              Upload file
            </button>
          </div>
        </div>

        <input
          ref={fileRef}
          type="file"
          accept=".json"
          className="hidden"
          onChange={onFile}
        />

        <textarea
          id="pkg-json"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={`{\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}`}
          className="h-64 w-full resize-none rounded-2xl border border-white/10 bg-black/35 p-4 font-mono text-sm text-white placeholder:text-white/24 focus:border-white/24 focus:outline-none"
          spellCheck={false}
        />
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
            <span>🚀</span>
            Audit Dependencies
          </>
        )}
      </button>
    </form>
  );
}

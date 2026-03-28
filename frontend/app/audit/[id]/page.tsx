import { use } from "react";
import Link from "next/link";
import AuditFeed from "@/components/AuditFeed";
import { DottedSurface } from "@/components/ui/dotted-surface";

export default function AuditPage(props: PageProps<"/audit/[id]">) {
  const { id } = use(props.params);

  return (
    <main className="relative min-h-screen overflow-hidden bg-background px-6 py-8 text-foreground">
      <DottedSurface className="opacity-55" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_18%,rgba(255,255,255,0.08),transparent_18%,transparent_50%)]" />
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">
        <div className="flex items-center justify-between rounded-3xl border border-white/10 bg-white/6 px-5 py-4 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🔍</span>
            <div>
              <h1 className="text-xl font-bold text-white">Specter</h1>
              <p className="font-mono text-xs text-white/40">{id}</p>
            </div>
          </div>
          <Link
            href="/"
            className="text-sm text-white/56 transition-colors hover:text-white"
          >
            ← New audit
          </Link>
        </div>

        <AuditFeed auditId={id} />
      </div>
    </main>
  );
}

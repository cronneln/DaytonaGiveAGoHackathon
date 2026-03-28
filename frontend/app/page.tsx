import PackageInput from "@/components/PackageInput";
import { DottedSurface } from "@/components/ui/dotted-surface";

export default function Home() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <DottedSurface />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_32%,rgba(255,255,255,0.1),transparent_20%,transparent_55%)]" />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-56 bg-gradient-to-t from-black via-black/60 to-transparent" />

      <section className="relative z-10 flex min-h-screen items-center justify-center px-6 py-20">
        <div className="w-full max-w-5xl">
          <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-1.5 text-xs font-medium uppercase tracking-[0.32em] text-white/72 backdrop-blur-md">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Daytona sandbox analysis
            </div>
            <h1 className="mt-7 font-mono text-5xl font-semibold tracking-tight text-white sm:text-7xl">
              Specter
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-white/68 sm:text-lg">
              Paste a <code className="rounded bg-white/8 px-2 py-1 font-mono text-sm">package.json</code> and
              get a runtime-backed risk report on every suspicious dependency without
              ever executing untrusted code on your machine.
            </p>
            <div className="mt-6 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-sm text-white/42">
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-sky-400" />
                One sandbox per package
              </span>
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-violet-300" />
                Streaming audit updates
              </span>
              <span className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                Safe package export
              </span>
            </div>
          </div>

          <div className="mx-auto mt-12 max-w-3xl rounded-[28px] border border-white/10 bg-white/6 p-4 shadow-[0_32px_120px_rgba(0,0,0,0.55)] backdrop-blur-2xl sm:p-6">
            <PackageInput />
          </div>

          <p className="mx-auto mt-5 max-w-2xl text-center text-xs uppercase tracking-[0.24em] text-white/28">
            Untrusted packages stay inside isolated Daytona workspaces
          </p>
        </div>
      </section>
    </main>
  );
}

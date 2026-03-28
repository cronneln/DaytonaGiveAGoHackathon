# 🔍 Dependency Auditor

> Point it at a `package.json`. Get a threat report on every suspicious dependency — what it **actually did at runtime**, not just what it claims to do.

Built for the **Daytona Hackathon** using isolated Daytona cloud sandboxes + Claude Opus 4.6.

## The core safety guarantee

Untrusted packages run and die inside Daytona workspaces. Your machine **never** executes them.

## How it works

1. **Triage** — Scores each dependency against the npm registry: download count, package age, maintainer changes, typosquatting detection
2. **Parallel sandboxes** — One Daytona workspace per suspicious package, all launched simultaneously
3. **Behavioral monitoring** — Each sandbox installs the package and monitors: outbound network calls, file system access, environment variable probing, CPU spikes (cryptominer detection)
4. **Threat synthesis** — Claude Opus 4.6 with adaptive thinking reads the runtime report and produces a severity rating + behavioral analysis
5. **Live dashboard** — Results stream back in real-time, red/amber/green per package

## Stack

| Layer | Technology |
|-------|-----------|
| Orchestrator | Python FastAPI + SSE |
| Sandboxes | Daytona Cloud (one workspace per package) |
| Harness | Node.js (~60 lines, no dependencies) |
| AI Scoring | Claude Opus 4.6 (adaptive thinking) |
| Dashboard | Next.js 16 App Router + Tailwind CSS 4 |

## Prerequisites

- Python 3.11+
- Node.js 18+
- [Daytona Cloud account](https://app.daytona.io) with API key
- [Anthropic API key](https://console.anthropic.com)

## Setup

### 1. API (FastAPI orchestrator)

```bash
cd api

# Copy and fill in your keys
cp .env.example .env

# Create virtualenv and install
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Dashboard (Next.js)

```bash
cd frontend
npm install
# .env.local is already configured for local dev (http://localhost:8000)
```

## Running

In terminal 1 — start the API:
```bash
cd api
source venv/bin/activate
uvicorn main:app --reload --port 8000
```

In terminal 2 — start the dashboard:
```bash
cd frontend
npm run dev
```

Open **http://localhost:3000**, paste a `package.json`, click **Audit Dependencies**.

## Demo

Use the **"Load example"** button to load a sample `package.json` that includes `event-stream@3.3.6` — the infamous 2018 supply chain attack that backdoored the `flatmap-stream` package to steal Bitcoin wallets.

Watch the sandbox spin up, detect the outbound connection attempt, and Claude flag it as **CRITICAL**.

## Behavioral signals detected

| Signal | Detection method |
|--------|-----------------|
| Outbound HTTP/HTTPS | `https.request` / `http.request` monkey-patch |
| Suspicious network destination | Claude analysis |
| File system writes | `fs.writeFile` override |
| Sensitive file reads | `fs.readFile` watching `.ssh`, `.aws`, `.env`, credentials |
| Env var probing | `process.env` Proxy on `KEY`, `SECRET`, `TOKEN`, `PASSWORD` |
| CPU spike / cryptominer | `os.cpus()` diff (>75% user time) |
| Crash on import | Exception caught and flagged |

## Stretch goal: Safe install

After audit completes, click **"Download safe package.json"** to get a filtered version with `critical` and `high` severity packages removed.

## Project structure

```
├── api/            FastAPI orchestrator (Python)
│   ├── main.py     Routes + SSE stream
│   ├── registry.py npm triage scoring
│   ├── sandbox.py  Daytona workspace lifecycle
│   ├── scorer.py   Claude threat synthesis
│   └── models.py   Pydantic models
├── harness/        Node.js sandbox harness
│   └── index.js    ~60 lines, zero dependencies
└── frontend/       Next.js 16 dashboard
    ├── app/        App Router pages
    └── components/ PackageCard, AuditFeed, PackageInput
```

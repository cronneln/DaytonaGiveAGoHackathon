"""
Dependency Auditor — FastAPI Orchestrator
"""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from models import (
    AuditRequest,
    AuditResponse,
    AuditSummary,
    PackageResult,
    Severity,
)
from registry import triage_dependencies
from sandbox import run_in_sandbox
from scorer import score_runtime, summarize_audit_results

# In-memory audit store: audit_id → { queue, results, summary }
_audits: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Clean up any lingering audit tasks on shutdown
    _audits.clear()


app = FastAPI(
    title="Dependency Auditor",
    description="Detect malicious npm packages using isolated Daytona sandboxes + Claude",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Audit orchestration ───────────────────────────────────────────────────────

async def _audit_single_package(
    audit_id: str,
    pkg_score,
) -> None:
    """Run one package through sandbox + scorer and push result to queue."""
    queue: asyncio.Queue = _audits[audit_id]["queue"]

    result = PackageResult(
        package=pkg_score.package,
        version=pkg_score.version,
        triage_score=pkg_score.score,
        triage_reasons=pkg_score.reasons,
        status="running",
    )

    # Signal sandbox starting
    await queue.put({"type": "package_update", "data": result.model_dump()})

    try:
        runtime = await run_in_sandbox(pkg_score.package)
        threat = await score_runtime(pkg_score.package, runtime)

        result.runtime = runtime
        result.severity = threat.severity
        result.behaviors = threat.behaviors
        result.summary = threat.summary
        result.explanation = threat.explanation
        result.status = "complete"
    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.severity = Severity.medium  # Unknown = treat with caution

    _audits[audit_id]["results"].append(result)
    await queue.put({"type": "package_result", "data": result.model_dump()})


async def _run_audit(audit_id: str, package_json: dict) -> None:
    """Full audit pipeline for all packages."""
    queue: asyncio.Queue = _audits[audit_id]["queue"]

    try:
        # Merge dependencies + devDependencies
        deps = {}
        deps.update(package_json.get("dependencies", {}))
        deps.update(package_json.get("devDependencies", {}))

        if not deps:
            await queue.put({"type": "error", "message": "No dependencies found in package.json"})
            return

        # Triage
        await queue.put({"type": "status", "message": f"Triaging {len(deps)} packages against npm registry..."})
        scores = await triage_dependencies(deps)

        await queue.put({
            "type": "triage_complete",
            "total": len(scores),
            "message": f"Launching {len(scores)} sandboxes in parallel...",
        })

        # Launch all sandboxes concurrently
        tasks = [_audit_single_package(audit_id, score) for score in scores]
        await asyncio.gather(*tasks)

        # Build summary
        results: list[PackageResult] = _audits[audit_id]["results"]
        summary = AuditSummary(
            audit_id=audit_id,
            total=len(results),
            critical=sum(1 for r in results if r.severity == Severity.critical),
            high=sum(1 for r in results if r.severity == Severity.high),
            medium=sum(1 for r in results if r.severity == Severity.medium),
            low=sum(1 for r in results if r.severity == Severity.low),
            safe=sum(1 for r in results if r.severity == Severity.safe),
            error=sum(1 for r in results if r.status == "error"),
        )
        _audits[audit_id]["summary"] = summary

        await queue.put({"type": "complete", "data": summary.model_dump()})

    except Exception as e:
        await queue.put({"type": "error", "message": f"Audit failed: {str(e)}"})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "dependency-auditor"}


@app.post("/api/v1/audit", response_model=AuditResponse)
async def start_audit(body: AuditRequest):
    deps = {}
    deps.update(body.package_json.get("dependencies", {}))
    deps.update(body.package_json.get("devDependencies", {}))

    if not deps:
        raise HTTPException(status_code=400, detail="No dependencies found in package.json")

    audit_id = str(uuid.uuid4())
    _audits[audit_id] = {
        "queue": asyncio.Queue(),
        "results": [],
        "summary": None,
        "ai_summary": None,
    }

    # Start audit in background
    asyncio.create_task(_run_audit(audit_id, body.package_json))

    return AuditResponse(
        audit_id=audit_id,
        total_packages=len(deps),
        message=f"Audit started for {len(deps)} packages",
    )


@app.get("/api/v1/audit/{audit_id}/stream")
async def stream_audit(audit_id: str, request: Request):
    if audit_id not in _audits:
        raise HTTPException(status_code=404, detail="Audit not found")

    async def event_generator() -> AsyncGenerator[dict, None]:
        queue: asyncio.Queue = _audits[audit_id]["queue"]
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=60.0)
                yield {"data": json.dumps(event)}

                if event.get("type") in ("complete", "error"):
                    break
            except asyncio.TimeoutError:
                # Keep-alive ping
                yield {"data": json.dumps({"type": "ping"})}

    return EventSourceResponse(event_generator())


@app.get("/api/v1/audit/{audit_id}/results")
async def get_results(audit_id: str):
    if audit_id not in _audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    results = _audits[audit_id]["results"]
    return [r.model_dump() for r in results]


@app.get("/api/v1/audit/{audit_id}/ai-summary")
async def audit_ai_summary(audit_id: str):
    """Cached executive summary across all packages (Claude)."""
    if audit_id not in _audits:
        raise HTTPException(status_code=404, detail="Audit not found")
    store = _audits[audit_id]
    if store.get("ai_summary"):
        return {"summary": store["ai_summary"]}
    results: list[PackageResult] = store["results"]
    if not results:
        raise HTTPException(status_code=400, detail="No results available yet")
    summary = await summarize_audit_results(results)
    store["ai_summary"] = summary
    return {"summary": summary}


@app.get("/api/v1/audit/{audit_id}/safe-package-json")
async def safe_package_json(audit_id: str):
    """Returns a filtered package.json with critical/high severity packages removed."""
    if audit_id not in _audits:
        raise HTTPException(status_code=404, detail="Audit not found")

    results: list[PackageResult] = _audits[audit_id]["results"]
    dangerous = {
        r.package
        for r in results
        if r.severity in (Severity.critical, Severity.high)
    }

    # We don't store the original package.json, so reconstruct from results
    safe_deps = {
        r.package: r.version
        for r in results
        if r.package not in dangerous
    }

    removed = [
        {"package": r.package, "severity": r.severity, "summary": r.summary}
        for r in results
        if r.package in dangerous
    ]

    return {
        "dependencies": safe_deps,
        "removed": removed,
        "message": f"Removed {len(removed)} dangerous package(s)",
    }

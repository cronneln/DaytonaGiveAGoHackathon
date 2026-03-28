"""
Claude Opus 4.6 Threat Synthesizer
Reads runtime behavioral reports and produces structured threat assessments.
"""

import asyncio
import json
import anthropic
from models import RuntimeReport, ThreatReport, Severity, PackageResult

client = anthropic.AsyncAnthropic()

SYSTEM_PROMPT = """You are a supply chain security analyst specializing in malicious npm packages.
You receive runtime behavioral reports from isolated sandbox executions and assess threat level.

Known malicious patterns:
- Outbound HTTP/HTTPS to unknown IPs or non-CDN domains during import = data exfiltration
- Reading .ssh, .aws, .env, credential files = credential harvesting
- Accessing SECRET, TOKEN, KEY, PASSWORD env vars = secret theft
- CPU spike >75% user time = cryptomining
- Crash on import can indicate obfuscated/corrupted malware
- Multiple suspicious signals together = critical threat

Use the report_threat tool to submit your structured assessment."""

THREAT_TOOL = {
    "name": "report_threat",
    "description": "Submit the structured threat assessment for the npm package",
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "safe"],
                "description": "Overall threat severity"
            },
            "behaviors": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of specific suspicious behaviors detected (empty if safe)"
            },
            "summary": {
                "type": "string",
                "description": "One-sentence human-readable summary"
            },
            "explanation": {
                "type": "string",
                "description": "Detailed analysis of findings and reasoning"
            }
        },
        "required": ["severity", "behaviors", "summary", "explanation"],
        "additionalProperties": False
    }
}


def _build_prompt(package_name: str, report: RuntimeReport) -> str:
    network_summary = ""
    # Truncate to 50 items to prevent oversized prompts exceeding token limits
    network_preview = report.networkCalls[:50]
    if report.networkCalls:
        hosts = list({c.get("host", "unknown") for c in report.networkCalls})
        network_summary = f"Made {len(report.networkCalls)} outbound network call(s) to: {', '.join(hosts)}"
    else:
        network_summary = "No outbound network calls detected"

    fs_writes_preview = report.fileSystemWrites[:50]
    fs_reads_sensitive = [r for r in report.fileSystemReads if r.get("suspicious")]
    fs_reads_preview = fs_reads_sensitive[:50]

    env_accessed = [e.get("key", "") for e in report.envVarAccess]
    env_preview = env_accessed[:50]

    return f"""Analyze the runtime behavior of npm package "{package_name}" and assess its threat level.

## Runtime Behavioral Report

**Network Activity:** {network_summary}
{json.dumps(network_preview, indent=2) if network_preview else ""}

**File System Writes:** {len(report.fileSystemWrites)} write(s)
{json.dumps(fs_writes_preview, indent=2) if fs_writes_preview else ""}

**Sensitive File Reads:** {len(fs_reads_sensitive)} suspicious read(s)
{json.dumps(fs_reads_preview, indent=2) if fs_reads_preview else ""}

**Environment Variable Access:** {len(env_accessed)} sensitive key(s) accessed
{json.dumps(env_preview, indent=2) if env_preview else ""}

**CPU user-time share (max across cores, 0–1):** {report.cpuUserRatioMax:.2f}
**CPU Anomaly (possible cryptominer):** {"YES - CPU usage spiked above 75%" if report.cpuAnomaly else "No"}

**Errors during import:** {report.errors if report.errors else "None"}

Assess the threat. Consider: is this normal package behavior (e.g. lodash making no network calls = safe),
or is this malicious (e.g. a utility making outbound calls to random IPs = critical)?"""


async def score_runtime(package_name: str, report: RuntimeReport) -> ThreatReport:
    """Use Claude Opus 4.6 to synthesize a threat report from runtime behavior."""
    prompt = _build_prompt(package_name, report)

    # Fast path: if no suspicious signals at all, skip Claude and return safe
    has_network = bool(report.networkCalls)
    has_sensitive_reads = any(r.get("suspicious") for r in report.fileSystemReads)
    has_env_access = bool(report.envVarAccess)
    has_cpu = report.cpuAnomaly
    has_errors = bool(report.errors)

    if not any([has_network, has_sensitive_reads, has_env_access, has_cpu, has_errors]):
        return ThreatReport(
            severity=Severity.safe,
            behaviors=[],
            summary=f"{package_name} showed no suspicious behavior during sandbox execution",
            explanation="No network calls, file access, environment variable probing, CPU anomalies, or errors detected.",
        )

    # Retry on transient API errors (rate limits and overload)
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            response = await client.messages.create(
                model="claude-opus-4-6",
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=[THREAT_TOOL],
                tool_choice={"type": "tool", "name": "report_threat"},
                messages=[{"role": "user", "content": prompt}],
            )
            break
        except anthropic.RateLimitError as exc:
            last_exc = exc
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                raise
        except anthropic.APIStatusError as exc:
            last_exc = exc
            if exc.status_code in (529,) and attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                raise

    tool_use = next(
        (block for block in response.content if block.type == "tool_use"),
        None,
    )
    if not tool_use:
        raise ValueError("Claude returned no tool_use content")

    data = tool_use.input
    try:
        severity = Severity(data["severity"])
    except (ValueError, KeyError):
        severity = Severity.medium  # Unknown response → treat with caution

    return ThreatReport(
        severity=severity,
        behaviors=data.get("behaviors", []),
        summary=data.get("summary", "Threat assessment unavailable"),
        explanation=data.get("explanation", ""),
    )


AUDIT_SUMMARY_SYSTEM = """You are a supply-chain security lead summarizing an automated npm dependency audit.
Write a clear executive summary for developers: prioritize risks, mention safe findings briefly, and suggest next steps.
Use short paragraphs and bullet points where helpful. Do not invent facts not present in the data."""


async def summarize_audit_results(results: list[PackageResult]) -> str:
    """High-level AI summary across all audited packages."""
    if not results:
        return "No packages were analyzed."

    errors = [r for r in results if r.status == "error"]
    issues = [
        r
        for r in results
        if r.status == "complete" and r.severity and r.severity != Severity.safe
    ]
    safe_n = sum(1 for r in results if r.status == "complete" and r.severity == Severity.safe)

    if not issues and not errors:
        return (
            "Every dependency finished sandbox analysis with no elevated risk signals. "
            "No suspicious network activity, credential access, or CPU anomalies were flagged."
        )

    if not issues and errors:
        names = ", ".join(e.package for e in errors[:12])
        extra = f" (+{len(errors) - 12} more)" if len(errors) > 12 else ""
        return (
            f"Sandbox runs failed for {len(errors)} package(s): {names}{extra}. "
            "Review the error details per package and retry. "
            "All other packages completed without suspicious behavior."
        )

    lines: list[str] = []
    for r in results:
        if r.status == "error":
            lines.append(f"- {r.package}: ERROR — {r.error or 'unknown error'}")
        elif r.status == "complete":
            sev = r.severity.value if r.severity else "unknown"
            lines.append(f"- {r.package} [{sev}]: {r.summary or '(no summary)'}")
        else:
            lines.append(f"- {r.package}: status={r.status}")

    user_prompt = (
        f"Analyzed packages: {len(results)}. "
        f"Completed with no issue: {safe_n}. "
        f"Elevated risk or non-safe: {len(issues)}. "
        f"Sandbox errors: {len(errors)}.\n\n"
        "Per-package outcomes:\n"
        + "\n".join(lines)
    )

    response = await client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1200,
        system=AUDIT_SUMMARY_SYSTEM,
        messages=[{"role": "user", "content": user_prompt}],
    )

    text_blocks = [b.text for b in response.content if b.type == "text"]
    return "\n\n".join(text_blocks).strip() or "Summary unavailable."

"""
Daytona Sandbox Manager
Creates isolated workspaces, runs the harness, collects results, destroys workspaces.
"""

import asyncio
import json
import os
from pathlib import Path
from models import RuntimeReport

# Load harness code once at startup
HARNESS_PATH = Path(__file__).parent.parent / "harness" / "index.js"


def _load_harness() -> str:
    with open(HARNESS_PATH, "r", encoding="utf-8") as f:
        return f.read()


HARNESS_CODE = _load_harness()


def _create_and_run(package_name: str) -> dict:
    """
    Synchronous Daytona operations (wrapped in asyncio.to_thread).
    Creates workspace → uploads harness → installs pkg → runs harness → deletes workspace.
    Returns raw runtime report dict.
    """
    from daytona import Daytona, CreateWorkspaceParams

    daytona = Daytona()
    workspace = None

    try:
        # Create isolated Node.js workspace
        params = CreateWorkspaceParams(language="javascript")
        workspace = daytona.create(params)

        # Upload the harness script
        try:
            workspace.fs.upload_file("/harness.js", HARNESS_CODE.encode("utf-8"))
        except AttributeError:
            # Some SDK versions use filesystem instead of fs
            try:
                workspace.filesystem.upload_file("/harness.js", HARNESS_CODE.encode("utf-8"))
            except AttributeError:
                # Fallback: write via exec
                escaped = HARNESS_CODE.replace("'", "'\\''")
                workspace.process.exec(f"printf '%s' '{escaped}' > /harness.js")

        # Install the package and run the harness
        # Capture only stdout (harness writes JSON to stdout, install logs to stderr)
        install_cmd = f"npm install {package_name} --prefix /app --no-save 2>/dev/null"
        run_cmd = f"NODE_PATH=/app/node_modules node /harness.js {package_name}"
        full_cmd = f"{install_cmd} && {run_cmd}"

        result = workspace.process.exec(full_cmd, timeout=45)
        output = result.result if hasattr(result, "result") else str(result)

        # Extract JSON from output (last non-empty line)
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        json_line = next((l for l in reversed(lines) if l.startswith("{")), None)

        if json_line:
            return json.loads(json_line)
        else:
            return {
                "package": package_name,
                "networkCalls": [],
                "fileSystemWrites": [],
                "fileSystemReads": [],
                "envVarAccess": [],
                "cpuAnomaly": False,
                "cpuUserRatioMax": 0.0,
                "errors": [f"Harness produced no JSON output. Raw: {output[:500]}"],
                "timestamp": 0,
            }

    except Exception as e:
        return {
            "package": package_name,
            "networkCalls": [],
            "fileSystemWrites": [],
            "fileSystemReads": [],
            "envVarAccess": [],
            "cpuAnomaly": False,
            "cpuUserRatioMax": 0.0,
            "errors": [f"Sandbox error: {str(e)}"],
            "timestamp": 0,
        }

    finally:
        if workspace is not None:
            try:
                daytona.delete(workspace)
            except Exception:
                pass  # Best-effort cleanup


async def run_in_sandbox(package_name: str) -> RuntimeReport:
    """Async wrapper — runs Daytona operations in a thread pool."""
    raw = await asyncio.to_thread(_create_and_run, package_name)
    return RuntimeReport(**{
        "package": raw.get("package", package_name),
        "networkCalls": raw.get("networkCalls", []),
        "fileSystemWrites": raw.get("fileSystemWrites", []),
        "fileSystemReads": raw.get("fileSystemReads", []),
        "envVarAccess": raw.get("envVarAccess", []),
        "cpuAnomaly": raw.get("cpuAnomaly", False),
        "cpuUserRatioMax": float(raw.get("cpuUserRatioMax", 0) or 0),
        "errors": raw.get("errors", []),
        "timestamp": raw.get("timestamp", 0),
    })

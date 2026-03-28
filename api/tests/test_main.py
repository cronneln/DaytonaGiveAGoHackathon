"""
Tests for api/main.py — FastAPI orchestrator.
Uses FastAPI TestClient with mocked sandbox + scorer to test all endpoints
and edge cases without live sandboxes or Claude API calls.
"""

import sys
import os
import json
import asyncio
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import RuntimeReport, ThreatReport, Severity, PackageResult


def make_safe_runtime():
    return RuntimeReport(
        package="test-pkg",
        networkCalls=[],
        fileSystemWrites=[],
        fileSystemReads=[],
        envVarAccess=[],
        cpuAnomaly=False,
        cpuUserRatioMax=0.0,
        errors=[],
        timestamp=0,
    )


def make_safe_threat(pkg="test-pkg"):
    return ThreatReport(
        severity=Severity.safe,
        behaviors=[],
        summary=f"{pkg} is safe",
        explanation="No signals detected.",
    )


def make_critical_threat(pkg="evil-pkg"):
    return ThreatReport(
        severity=Severity.critical,
        behaviors=["network exfiltration"],
        summary=f"{pkg} exfiltrates credentials",
        explanation="Outbound network calls to attacker.io",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test client fixture
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Create a test client with sandbox and scorer mocked to avoid live calls."""
    with patch("main.run_in_sandbox", new_callable=AsyncMock, return_value=make_safe_runtime()), \
         patch("main.score_runtime", new_callable=AsyncMock, return_value=make_safe_threat()), \
         patch("main.triage_dependencies", new_callable=AsyncMock) as mock_triage:

        from models import SuspicionScore
        mock_triage.return_value = [
            SuspicionScore(package="lodash", version="4.17.21", score=0, reasons=["No red flags"]),
        ]

        from main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/v1/audit — input validation
# ─────────────────────────────────────────────────────────────────────────────

class TestStartAudit:
    def test_valid_package_json_returns_200_with_audit_id(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": {"lodash": "4.17.21"}}
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "audit_id" in body
        assert body["total_packages"] == 1

    def test_with_dev_dependencies(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"devDependencies": {"jest": "29.0.0"}}
        })
        assert resp.status_code == 200
        assert resp.json()["total_packages"] == 1

    def test_merges_dependencies_and_dev_dependencies(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {
                "dependencies": {"lodash": "4.17.21"},
                "devDependencies": {"jest": "29.0.0"},
            }
        })
        assert resp.status_code == 200
        assert resp.json()["total_packages"] == 2

    def test_empty_package_json_returns_400(self, client):
        resp = client.post("/api/v1/audit", json={"package_json": {}})
        assert resp.status_code == 400

    def test_empty_dependencies_returns_400(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": {}}
        })
        assert resp.status_code == 400

    def test_dependencies_as_list_returns_400(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": ["lodash", "react"]}
        })
        assert resp.status_code == 400

    def test_dev_dependencies_as_string_returns_400(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"devDependencies": "jest"}
        })
        assert resp.status_code == 400

    def test_dep_value_as_integer_returns_400(self, client):
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": {"lodash": 4}}
        })
        assert resp.status_code == 400

    def test_dep_key_as_non_string_returns_400(self, client):
        # JSON keys are always strings, but we test the validation still runs
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": {"lodash": {"nested": "object"}}}
        })
        assert resp.status_code == 400

    def test_101_packages_returns_400(self, client):
        deps = {f"pkg{i}": "1.0.0" for i in range(101)}
        resp = client.post("/api/v1/audit", json={
            "package_json": {"dependencies": deps}
        })
        assert resp.status_code == 400
        assert "100" in resp.json()["detail"]

    def test_exactly_100_packages_returns_200(self, client):
        deps = {f"pkg{i}": "1.0.0" for i in range(100)}

        from models import SuspicionScore
        mock_scores = [SuspicionScore(package=k, version="1.0.0", score=0, reasons=[]) for k in deps]

        with patch("main.triage_dependencies", new_callable=AsyncMock, return_value=mock_scores):
            resp = client.post("/api/v1/audit", json={
                "package_json": {"dependencies": deps}
            })
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/v1/audit/{id}/stream
# ─────────────────────────────────────────────────────────────────────────────

class TestStreamAudit:
    def test_unknown_audit_id_returns_404(self, client):
        resp = client.get(f"/api/v1/audit/{uuid.uuid4()}/stream")
        assert resp.status_code == 404

    def test_invalid_uuid_format_returns_404(self, client):
        resp = client.get("/api/v1/audit/not-a-uuid/stream")
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/v1/audit/{id}/results
# ─────────────────────────────────────────────────────────────────────────────

class TestGetResults:
    def test_unknown_audit_id_returns_404(self, client):
        resp = client.get(f"/api/v1/audit/{uuid.uuid4()}/results")
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/v1/audit/{id}/ai-summary
# ─────────────────────────────────────────────────────────────────────────────

class TestAiSummary:
    def test_unknown_audit_id_returns_404(self, client):
        resp = client.get(f"/api/v1/audit/{uuid.uuid4()}/ai-summary")
        assert resp.status_code == 404

    def test_audit_with_no_results_returns_400(self, client):
        # Start an audit but intercept before any results are added
        from main import _audits
        audit_id = str(uuid.uuid4())
        _audits[audit_id] = {"queue": asyncio.Queue(), "results": [], "summary": None, "ai_summary": None}

        resp = client.get(f"/api/v1/audit/{audit_id}/ai-summary")
        assert resp.status_code == 400

        del _audits[audit_id]

    def test_cached_summary_returned_without_second_claude_call(self, client):
        from main import _audits
        audit_id = str(uuid.uuid4())
        cached = "Previously computed summary."
        _audits[audit_id] = {
            "queue": asyncio.Queue(),
            "results": [MagicMock()],
            "summary": None,
            "ai_summary": cached,
        }

        with patch("main.summarize_audit_results", new_callable=AsyncMock) as mock_summary:
            resp = client.get(f"/api/v1/audit/{audit_id}/ai-summary")

        mock_summary.assert_not_called()
        assert resp.json()["summary"] == cached

        del _audits[audit_id]


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/v1/audit/{id}/safe-package-json
# ─────────────────────────────────────────────────────────────────────────────

class TestSafePackageJson:
    def test_unknown_audit_id_returns_404(self, client):
        resp = client.get(f"/api/v1/audit/{uuid.uuid4()}/safe-package-json")
        assert resp.status_code == 404

    def _setup_audit_with_results(self, results):
        from main import _audits
        audit_id = str(uuid.uuid4())
        _audits[audit_id] = {
            "queue": asyncio.Queue(),
            "results": results,
            "summary": None,
            "ai_summary": None,
        }
        return audit_id

    def test_critical_package_excluded(self, client):
        results = [
            PackageResult(package="evil-pkg", version="1.0.0", triage_score=9,
                          triage_reasons=[], severity=Severity.critical, status="complete"),
            PackageResult(package="safe-pkg", version="2.0.0", triage_score=0,
                          triage_reasons=[], severity=Severity.safe, status="complete"),
        ]
        audit_id = self._setup_audit_with_results(results)

        try:
            resp = client.get(f"/api/v1/audit/{audit_id}/safe-package-json")
            assert resp.status_code == 200
            body = resp.json()
            assert "evil-pkg" not in body["dependencies"]
            assert "safe-pkg" in body["dependencies"]
            assert len(body["removed"]) == 1
        finally:
            from main import _audits
            del _audits[audit_id]

    def test_high_severity_package_excluded(self, client):
        results = [
            PackageResult(package="risky-pkg", version="1.0.0", triage_score=7,
                          triage_reasons=[], severity=Severity.high, status="complete"),
        ]
        audit_id = self._setup_audit_with_results(results)

        try:
            resp = client.get(f"/api/v1/audit/{audit_id}/safe-package-json")
            body = resp.json()
            assert "risky-pkg" not in body["dependencies"]
            assert len(body["removed"]) == 1
        finally:
            from main import _audits
            del _audits[audit_id]

    def test_errored_package_excluded_from_safe_deps(self, client):
        """Packages that errored during sandbox run should NOT appear in safe deps."""
        results = [
            PackageResult(package="error-pkg", version="1.0.0", triage_score=3,
                          triage_reasons=[], severity=None, status="error",
                          error="Sandbox timed out"),
            PackageResult(package="ok-pkg", version="2.0.0", triage_score=0,
                          triage_reasons=[], severity=Severity.safe, status="complete"),
        ]
        audit_id = self._setup_audit_with_results(results)

        try:
            resp = client.get(f"/api/v1/audit/{audit_id}/safe-package-json")
            body = resp.json()
            assert "error-pkg" not in body["dependencies"]
            assert "ok-pkg" in body["dependencies"]
        finally:
            from main import _audits
            del _audits[audit_id]

    def test_medium_severity_included_in_safe_deps(self, client):
        """medium/low/safe packages should all appear in safe deps."""
        results = [
            PackageResult(package="med-pkg", version="1.0.0", triage_score=3,
                          triage_reasons=[], severity=Severity.medium, status="complete"),
            PackageResult(package="low-pkg", version="1.0.0", triage_score=1,
                          triage_reasons=[], severity=Severity.low, status="complete"),
            PackageResult(package="safe-pkg", version="1.0.0", triage_score=0,
                          triage_reasons=[], severity=Severity.safe, status="complete"),
        ]
        audit_id = self._setup_audit_with_results(results)

        try:
            resp = client.get(f"/api/v1/audit/{audit_id}/safe-package-json")
            body = resp.json()
            assert "med-pkg" in body["dependencies"]
            assert "low-pkg" in body["dependencies"]
            assert "safe-pkg" in body["dependencies"]
            assert len(body["removed"]) == 0
        finally:
            from main import _audits
            del _audits[audit_id]

    def test_empty_results_returns_empty_dependencies(self, client):
        audit_id = self._setup_audit_with_results([])

        try:
            resp = client.get(f"/api/v1/audit/{audit_id}/safe-package-json")
            assert resp.status_code == 200
            assert resp.json()["dependencies"] == {}
        finally:
            from main import _audits
            del _audits[audit_id]


# ─────────────────────────────────────────────────────────────────────────────
# _run_audit — internal resilience
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRunAuditResilience:
    async def test_non_dict_dev_dependencies_handled_gracefully(self):
        """devDependencies as a non-dict should not crash _run_audit."""
        from main import _run_audit, _audits
        audit_id = str(uuid.uuid4())
        _audits[audit_id] = {
            "queue": asyncio.Queue(),
            "results": [],
            "summary": None,
            "ai_summary": None,
        }

        package_json = {
            "dependencies": {"lodash": "4.17.21"},
            "devDependencies": "should-be-a-dict",  # malformed
        }

        with patch("main.triage_dependencies", new_callable=AsyncMock, return_value=[]), \
             patch("main.run_in_sandbox", new_callable=AsyncMock, return_value=make_safe_runtime()), \
             patch("main.score_runtime", new_callable=AsyncMock, return_value=make_safe_threat()):
            await _run_audit(audit_id, package_json)

        # Should not crash, should process the valid dependencies
        queue = _audits[audit_id]["queue"]
        events = []
        while not queue.empty():
            events.append(await queue.get())

        event_types = [e["type"] for e in events]
        assert "error" not in event_types or any("complete" in t for t in event_types)

        del _audits[audit_id]

    async def test_empty_package_json_sends_error_event(self):
        from main import _run_audit, _audits
        audit_id = str(uuid.uuid4())
        _audits[audit_id] = {
            "queue": asyncio.Queue(),
            "results": [],
            "summary": None,
            "ai_summary": None,
        }

        await _run_audit(audit_id, {})

        queue = _audits[audit_id]["queue"]
        event = await queue.get()
        assert event["type"] == "error"
        assert "No dependencies" in event["message"]

        del _audits[audit_id]

"""
Tests for api/scorer.py — Claude Opus 4.6 threat synthesizer.
Mocks the Anthropic client to test all scoring paths without live API calls.
"""

import sys
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import RuntimeReport, ThreatReport, Severity, PackageResult
from scorer import _build_prompt, score_runtime, summarize_audit_results


def make_clean_report(pkg="test-pkg"):
    """RuntimeReport with no suspicious signals → fast-path safe."""
    return RuntimeReport(
        package=pkg,
        networkCalls=[],
        fileSystemWrites=[],
        fileSystemReads=[],
        envVarAccess=[],
        cpuAnomaly=False,
        cpuUserRatioMax=0.0,
        errors=[],
        timestamp=0,
    )


def make_suspicious_report(pkg="evil-pkg"):
    """RuntimeReport with multiple suspicious signals."""
    return RuntimeReport(
        package=pkg,
        networkCalls=[
            {"protocol": "https", "host": "attacker.io", "port": 443, "path": "/steal", "time": 1000},
        ],
        fileSystemWrites=[],
        fileSystemReads=[
            {"path": "/home/user/.ssh/id_rsa", "suspicious": True, "time": 1001},
        ],
        envVarAccess=[
            {"key": "AWS_SECRET_KEY", "time": 1002},
        ],
        cpuAnomaly=False,
        cpuUserRatioMax=0.1,
        errors=[],
        timestamp=1000,
    )


def make_tool_use_response(severity="critical", behaviors=None, summary="Malicious", explanation="Details"):
    """Build a mock Anthropic API response containing a tool_use block."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.input = {
        "severity": severity,
        "behaviors": behaviors or ["network exfiltration"],
        "summary": summary,
        "explanation": explanation,
    }
    response = MagicMock()
    response.content = [tool_block]
    return response


# ─────────────────────────────────────────────────────────────────────────────
# _build_prompt
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildPrompt:
    def test_clean_report_has_no_network(self):
        report = make_clean_report()
        prompt = _build_prompt("lodash", report)
        assert "No outbound network calls detected" in prompt

    def test_network_calls_appear_in_prompt(self):
        report = make_suspicious_report()
        prompt = _build_prompt("evil-pkg", report)
        assert "attacker.io" in prompt

    def test_env_vars_appear_in_prompt(self):
        report = make_suspicious_report()
        prompt = _build_prompt("evil-pkg", report)
        assert "AWS_SECRET_KEY" in prompt

    def test_truncates_large_network_calls_to_50(self):
        report = RuntimeReport(
            package="flood-pkg",
            networkCalls=[{"protocol": "http", "host": f"h{i}.com", "port": 80, "path": "/", "time": i}
                          for i in range(200)],
            fileSystemWrites=[],
            fileSystemReads=[],
            envVarAccess=[],
            cpuAnomaly=False,
            cpuUserRatioMax=0.0,
            errors=[],
            timestamp=0,
        )
        prompt = _build_prompt("flood-pkg", report)
        # The prompt should mention 200 calls in the summary but only show 50
        assert "200 outbound" in prompt
        # h50.com and beyond should not appear in the JSON dump
        assert "h50.com" not in prompt
        assert "h0.com" in prompt  # first 50 are included

    def test_cpu_anomaly_highlighted(self):
        report = RuntimeReport(
            package="miner-pkg",
            networkCalls=[],
            fileSystemWrites=[],
            fileSystemReads=[],
            envVarAccess=[],
            cpuAnomaly=True,
            cpuUserRatioMax=0.92,
            errors=[],
            timestamp=0,
        )
        prompt = _build_prompt("miner-pkg", report)
        assert "YES" in prompt or "75%" in prompt

    def test_errors_appear_in_prompt(self):
        report = RuntimeReport(
            package="crash-pkg",
            networkCalls=[],
            fileSystemWrites=[],
            fileSystemReads=[],
            envVarAccess=[],
            cpuAnomaly=False,
            cpuUserRatioMax=0.0,
            errors=["Cannot find module 'missing'"],
            timestamp=0,
        )
        prompt = _build_prompt("crash-pkg", report)
        assert "Cannot find module" in prompt


# ─────────────────────────────────────────────────────────────────────────────
# score_runtime — fast path
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestScoreRuntimeFastPath:
    async def test_clean_report_returns_safe_without_calling_claude(self):
        report = make_clean_report()
        with patch("scorer.client") as mock_client:
            result = await score_runtime("lodash", report)
        mock_client.messages.create.assert_not_called()
        assert result.severity == Severity.safe
        assert result.behaviors == []

    async def test_report_with_only_errors_calls_claude(self):
        """Errors are a suspicious signal — must invoke Claude."""
        report = RuntimeReport(
            package="crash-pkg",
            networkCalls=[],
            fileSystemWrites=[],
            fileSystemReads=[],
            envVarAccess=[],
            cpuAnomaly=False,
            cpuUserRatioMax=0.0,
            errors=["SyntaxError: unexpected token"],
            timestamp=0,
        )
        mock_response = make_tool_use_response("medium", ["import crash"])
        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("crash-pkg", report)
        mock_client.messages.create.assert_called_once()
        assert result.severity == Severity.medium

    async def test_report_with_network_calls_calls_claude(self):
        report = make_suspicious_report()
        mock_response = make_tool_use_response("critical")
        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("evil-pkg", report)
        assert result.severity == Severity.critical

    async def test_report_with_cpu_anomaly_calls_claude(self):
        report = RuntimeReport(
            package="miner-pkg",
            networkCalls=[],
            fileSystemWrites=[],
            fileSystemReads=[],
            envVarAccess=[],
            cpuAnomaly=True,
            cpuUserRatioMax=0.88,
            errors=[],
            timestamp=0,
        )
        mock_response = make_tool_use_response("high", ["cryptomining CPU spike"])
        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("miner-pkg", report)
        assert result.severity == Severity.high


# ─────────────────────────────────────────────────────────────────────────────
# score_runtime — Claude response handling
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestScoreRuntimeClaudeResponse:
    async def test_valid_critical_response(self):
        report = make_suspicious_report()
        mock_response = make_tool_use_response(
            severity="critical",
            behaviors=["network exfiltration", "credential harvesting"],
            summary="Package exfiltrates SSH keys to attacker.io",
            explanation="Multiple signals detected.",
        )
        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("evil-pkg", report)

        assert result.severity == Severity.critical
        assert "network exfiltration" in result.behaviors
        assert "attacker.io" in result.summary or result.summary != ""

    async def test_unknown_severity_falls_back_to_medium(self):
        """Claude returning an unexpected severity value should not crash."""
        report = make_suspicious_report()
        mock_response = make_tool_use_response(severity="unknown_severity_xyz")
        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("evil-pkg", report)

        assert result.severity == Severity.medium

    async def test_no_tool_use_block_raises_value_error(self):
        """Missing tool_use block should raise ValueError (caught upstream)."""
        report = make_suspicious_report()
        mock_response = MagicMock()
        text_block = MagicMock()
        text_block.type = "text"
        mock_response.content = [text_block]

        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            with pytest.raises(ValueError, match="no tool_use content"):
                await score_runtime("evil-pkg", report)

    async def test_missing_behaviors_key_returns_empty_list(self):
        report = make_suspicious_report()
        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.input = {
            "severity": "high",
            # "behaviors" key intentionally missing
            "summary": "Suspicious",
            "explanation": "Details",
        }
        mock_response = MagicMock()
        mock_response.content = [tool_block]

        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await score_runtime("evil-pkg", report)

        assert result.behaviors == []

    async def test_all_severity_levels_parsed_correctly(self):
        report = make_suspicious_report()
        for sev in ["critical", "high", "medium", "low", "safe"]:
            mock_response = make_tool_use_response(severity=sev)
            with patch("scorer.client") as mock_client:
                mock_client.messages.create = AsyncMock(return_value=mock_response)
                result = await score_runtime("test-pkg", report)
            assert result.severity == Severity(sev)


# ─────────────────────────────────────────────────────────────────────────────
# score_runtime — retry logic
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestScoreRuntimeRetry:
    async def test_rate_limit_retries_and_succeeds(self):
        import anthropic as ant
        report = make_suspicious_report()
        mock_response = make_tool_use_response("high")
        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ant.RateLimitError("Rate limited", response=MagicMock(), body={})
            return mock_response

        with patch("scorer.client") as mock_client, \
             patch("scorer.asyncio.sleep", new_callable=AsyncMock):
            mock_client.messages.create = side_effect
            result = await score_runtime("evil-pkg", report)

        assert call_count == 2
        assert result.severity == Severity.high

    async def test_rate_limit_exhausted_raises(self):
        import anthropic as ant
        report = make_suspicious_report()

        async def always_rate_limit(*args, **kwargs):
            raise ant.RateLimitError("Rate limited", response=MagicMock(), body={})

        with patch("scorer.client") as mock_client, \
             patch("scorer.asyncio.sleep", new_callable=AsyncMock):
            mock_client.messages.create = always_rate_limit
            with pytest.raises(ant.RateLimitError):
                await score_runtime("evil-pkg", report)


# ─────────────────────────────────────────────────────────────────────────────
# summarize_audit_results
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestSummarizeAuditResults:
    async def test_empty_results_returns_no_packages_message(self):
        result = await summarize_audit_results([])
        assert "No packages" in result

    async def test_all_safe_no_claude_call(self):
        """When all packages are safe and no errors, returns early without Claude."""
        results = [
            PackageResult(package="lodash", version="4.17.21", triage_score=0,
                          triage_reasons=[], severity=Severity.safe, status="complete"),
        ]
        with patch("scorer.client") as mock_client:
            result = await summarize_audit_results(results)
        mock_client.messages.create.assert_not_called()
        assert "no elevated risk" in result.lower() or "no" in result.lower()

    async def test_errors_only_returns_error_message_without_claude(self):
        results = [
            PackageResult(package="bad-pkg", version="1.0.0", triage_score=5,
                          triage_reasons=[], status="error", error="Sandbox failed"),
        ]
        with patch("scorer.client") as mock_client:
            result = await summarize_audit_results(results)
        mock_client.messages.create.assert_not_called()
        assert "bad-pkg" in result or "error" in result.lower()

    async def test_issues_present_calls_claude(self):
        results = [
            PackageResult(package="evil-pkg", version="1.0.0", triage_score=9,
                          triage_reasons=[], severity=Severity.critical, status="complete",
                          summary="Exfiltrates SSH keys"),
        ]
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "This package is critically dangerous."
        mock_response = MagicMock()
        mock_response.content = [text_block]

        with patch("scorer.client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await summarize_audit_results(results)

        mock_client.messages.create.assert_called_once()
        assert "dangerous" in result.lower()

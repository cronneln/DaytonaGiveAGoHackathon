"""
npm Registry Triage Scorer
Fetches metadata for each dependency and assigns a suspicion score.
High score = more suspicious = audit first.
"""

import asyncio
import httpx
from datetime import datetime, timezone, timedelta
from models import SuspicionScore

# Top 100 most downloaded npm packages for typosquatting detection
TOP_PACKAGES = {
    "lodash", "chalk", "react", "express", "axios", "moment", "webpack",
    "typescript", "eslint", "prettier", "jest", "babel", "next", "vue",
    "angular", "jquery", "underscore", "async", "request", "commander",
    "yargs", "dotenv", "uuid", "debug", "semver", "glob", "minimist",
    "mkdirp", "rimraf", "fs-extra", "cross-env", "nodemon", "pm2",
    "mongoose", "sequelize", "knex", "redis", "socket.io", "cors",
    "helmet", "passport", "jsonwebtoken", "bcrypt", "multer", "sharp",
    "puppeteer", "playwright", "cheerio", "node-fetch", "got",
    "superagent", "bluebird", "rxjs", "immutable", "ramda", "date-fns",
    "classnames", "styled-components", "tailwindcss", "postcss",
    "rollup", "vite", "esbuild", "turbopack", "swc", "babel-core",
    "react-dom", "react-router", "redux", "mobx", "zustand", "recoil",
    "graphql", "apollo-client", "prisma", "typeorm", "mikro-orm",
    "fastify", "koa", "hapi", "nestjs", "strapi", "gatsby", "nuxt",
    "electron", "tauri", "capacitor", "expo", "react-native",
    "winston", "pino", "bunyan", "morgan", "compression", "body-parser",
    "cookie-parser", "express-session", "connect-flash", "validator",
    "zod", "yup", "joi", "ajv", "supertest", "mocha", "chai", "sinon",
}


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def typosquat_score(package_name: str) -> tuple[int, list[str]]:
    """Check if package name is suspiciously close to a popular package."""
    # Strip scope prefix for comparison
    name = package_name.split("/")[-1].lower()
    # If this is itself a known popular package, do not mark it as typosquatting.
    if name in TOP_PACKAGES:
        return 0, []
    reasons = []
    score = 0
    for popular in TOP_PACKAGES:
        dist = levenshtein(name, popular)
        if 0 < dist <= 2 and name != popular:
            score += 4
            reasons.append(f"Name '{name}' is {dist} edit(s) away from popular package '{popular}' (possible typosquatting)")
            break  # One match is enough
    return score, reasons


async def fetch_npm_metadata(client: httpx.AsyncClient, package_name: str) -> dict:
    """Fetch package metadata from npm registry."""
    # Handle scoped packages
    encoded = package_name.replace("/", "%2F")
    try:
        resp = await client.get(
            f"https://registry.npmjs.org/{encoded}",
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


async def fetch_npm_downloads(client: httpx.AsyncClient, package_name: str) -> int:
    """Fetch weekly download count from npm downloads API."""
    encoded = package_name.replace("/", "%2F")
    try:
        resp = await client.get(
            f"https://api.npmjs.org/downloads/point/last-week/{encoded}",
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("downloads", 0)
    except Exception:
        pass
    return 0


async def score_package(
    client: httpx.AsyncClient,
    package_name: str,
    version: str,
) -> SuspicionScore:
    """Score a single package for suspicion."""
    score = 0
    reasons: list[str] = []

    # Run metadata + downloads fetch concurrently
    meta_task = asyncio.create_task(fetch_npm_metadata(client, package_name))
    dl_task = asyncio.create_task(fetch_npm_downloads(client, package_name))
    meta, weekly_downloads = await asyncio.gather(meta_task, dl_task)

    # ── Download count ────────────────────────────────────────────────────────
    if weekly_downloads == 0:
        score += 3
        reasons.append("Package not found in npm downloads API (unpublished or very new)")
    elif weekly_downloads < 100:
        score += 3
        reasons.append(f"Very low weekly downloads: {weekly_downloads:,}")
    elif weekly_downloads < 1_000:
        score += 2
        reasons.append(f"Low weekly downloads: {weekly_downloads:,}")
    elif weekly_downloads < 10_000:
        score += 1
        reasons.append(f"Moderate weekly downloads: {weekly_downloads:,}")

    if meta:
        now = datetime.now(timezone.utc)

        # ── Package age ───────────────────────────────────────────────────────
        time_section = meta.get("time", {})
        created_str = time_section.get("created", "")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (now - created).days
                if age_days < 30:
                    score += 3
                    reasons.append(f"Package is only {age_days} days old")
                elif age_days < 90:
                    score += 2
                    reasons.append(f"Package is only {age_days} days old")
            except ValueError:
                pass

        # ── Recent maintainer changes ─────────────────────────────────────────
        modified_str = time_section.get("modified", "")
        if modified_str:
            try:
                modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                days_since_modified = (now - modified).days
                maintainers = meta.get("maintainers", [])
                if days_since_modified < 30 and len(maintainers) == 1:
                    score += 2
                    reasons.append(f"Modified {days_since_modified} days ago with only 1 maintainer")
            except ValueError:
                pass

        # ── No homepage or repository ─────────────────────────────────────────
        if not meta.get("homepage") and not meta.get("repository"):
            score += 1
            reasons.append("No homepage or repository URL listed")

        # ── Suspicious keywords in description ────────────────────────────────
        desc = (meta.get("description") or "").lower()
        suspicious_keywords = ["stealer", "miner", "crypto", "hack", "exploit", "payload"]
        for kw in suspicious_keywords:
            if kw in desc:
                score += 3
                reasons.append(f"Suspicious keyword in description: '{kw}'")

    # ── Typosquatting ─────────────────────────────────────────────────────────
    typo_score, typo_reasons = typosquat_score(package_name)
    score += typo_score
    reasons.extend(typo_reasons)

    return SuspicionScore(
        package=package_name,
        version=version,
        score=score,
        reasons=reasons if reasons else ["No obvious red flags in registry metadata"],
    )


async def triage_dependencies(deps: dict[str, str]) -> list[SuspicionScore]:
    """Score all dependencies concurrently and return sorted by suspicion (highest first)."""
    async with httpx.AsyncClient() as client:
        tasks = [
            score_package(client, pkg, ver)
            for pkg, ver in deps.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    scores: list[SuspicionScore] = []
    for pkg, result in zip(deps.keys(), results):
        if isinstance(result, SuspicionScore):
            scores.append(result)
        else:
            # Failed to score — treat as suspicious
            scores.append(SuspicionScore(
                package=pkg,
                version=deps[pkg],
                score=2,
                reasons=["Failed to fetch registry metadata"],
            ))

    return sorted(scores, key=lambda s: s.score, reverse=True)

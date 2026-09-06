"""AI explanation layer.

Sends STIG rules to the Anthropic API in small batches and attaches a
plain-English summary, a triage bucket, and an automation flag to each
rule. Results are cached on disk (keyed by rule id + model) so re-runs
cost nothing.

Requires the ANTHROPIC_API_KEY environment variable.
No third-party dependencies — uses urllib from the standard library.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-5"
BATCH_SIZE = 8

TRIAGE_VALUES = ["quick-win", "config-profile", "needs-judgment", "risky-change"]

SYSTEM_PROMPT = """\
You are a senior security engineer helping a colleague work through a DISA
STIG checklist. For each rule provided, respond with practical, accurate
guidance. You must respond with ONLY a JSON array, one object per rule,
each with these keys:
- "stig_id": copied verbatim from the input
- "summary": 1-2 plain-English sentences: what this rule actually makes
  you do and why it matters, written for an engineer, no jargon
- "triage": exactly one of "quick-win" (fast, low-risk to apply),
  "config-profile" (needs an MDM/configuration profile deployed),
  "needs-judgment" (depends on environment or mission; a human must
  decide), "risky-change" (can lock users out or break workflows if
  applied blindly)
- "automation": "automatable" if check and fix can both be scripted,
  otherwise "manual"
- "caution": one sentence on what could go wrong applying this, or ""

Do not invent commands that are not in the check/fix text. Output only
the JSON array, no markdown fences, no commentary."""


class ExplainError(RuntimeError):
    pass


def _http_post(payload: dict, api_key: str) -> dict:
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read())


def _call_api(rules_payload: list, model: str, api_key: str) -> list:
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": json.dumps(rules_payload, ensure_ascii=False),
        }],
    }
    last_err = None
    for attempt in range(4):
        try:
            data = _http_post(payload, api_key)
            text = "".join(
                block.get("text", "")
                for block in data.get("content", [])
                if block.get("type") == "text"
            ).strip()
            if text.startswith("```"):
                text = text.strip("`")
                text = text[text.find("["):text.rfind("]") + 1]
            return json.loads(text)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            if e.code in (429, 500, 502, 503, 529) and attempt < 3:
                time.sleep(2 ** (attempt + 1))
                last_err = f"HTTP {e.code}: {body}"
                continue
            raise ExplainError(f"Anthropic API error HTTP {e.code}: {body}")
        except (json.JSONDecodeError, KeyError) as e:
            last_err = f"unparseable model response: {e}"
            if attempt < 3:
                continue
    raise ExplainError(f"giving up after retries: {last_err}")


def _cache_path(source: Path) -> Path:
    return source.with_suffix(".ai-cache.json")


def explain(benchmark, source_path, model: str = DEFAULT_MODEL,
            limit: int | None = None, progress=True) -> int:
    """Attach AI annotations to benchmark.rules in place.

    Returns the number of rules annotated via the API (cache hits not
    counted). Raises ExplainError on unrecoverable API failures.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise ExplainError(
            "ANTHROPIC_API_KEY is not set. Get a key at "
            "https://console.anthropic.com and run:\n"
            '  export ANTHROPIC_API_KEY="sk-ant-..."'
        )

    cache_file = _cache_path(Path(source_path))
    cache = {}
    if cache_file.exists():
        try:
            cache = json.loads(cache_file.read_text())
        except json.JSONDecodeError:
            cache = {}

    # Also honour annotations committed to the repository (written by the
    # stig-explain skill or by an earlier --explain run), so that a user
    # who never sets an API key still gets the explanations.
    repo_ann = Path(__file__).resolve().parents[1] / "annotations" / cache_file.name
    if repo_ann.exists():
        try:
            for k, v in json.loads(repo_ann.read_text()).items():
                cache.setdefault(k, v)
        except json.JSONDecodeError:
            pass
    by_sid = {k.split(":", 1)[1]: v for k, v in cache.items() if ":" in k}

    todo = []
    for rule in benchmark.rules:
        key = f"{model}:{rule.stig_id}"
        if key in cache:
            rule.ai = cache[key]
        elif rule.stig_id in by_sid:          # annotated by another model/skill
            rule.ai = by_sid[rule.stig_id]
        else:
            todo.append(rule)

    if limit is not None:
        todo = todo[:limit]

    api_calls = 0
    for i in range(0, len(todo), BATCH_SIZE):
        batch = todo[i:i + BATCH_SIZE]
        payload = [{
            "stig_id": r.stig_id,
            "severity": r.severity,
            "title": r.title,
            "discussion": r.discussion[:1500],
            "check_text": r.check_text[:1500],
            "fix_text": r.fix_text[:1500],
        } for r in batch]

        if progress:
            done = min(i + BATCH_SIZE, len(todo))
            print(f"  AI: annotating {done}/{len(todo)} rules...",
                  file=sys.stderr)

        results = _call_api(payload, model, api_key)
        by_id = {item.get("stig_id"): item for item in results
                 if isinstance(item, dict)}
        for r in batch:
            item = by_id.get(r.stig_id)
            if not item:
                continue
            triage = item.get("triage", "")
            r.ai = {
                "summary": str(item.get("summary", "")).strip(),
                "triage": triage if triage in TRIAGE_VALUES else "needs-judgment",
                "automation": item.get("automation", "manual"),
                "caution": str(item.get("caution", "")).strip(),
                "model": model,
            }
            cache[f"{model}:{r.stig_id}"] = r.ai
            api_calls += 1
        cache_file.write_text(json.dumps(cache, indent=1))

    return api_calls

"""Authoring: derive candidate checks from STIG check text.

This is the AI-authoring half of the pipeline — and the first honest finding
of building it is that for the macOS STIG, most of the work does not need a
model at all. DISA's macOS check text is already written as a shell snippet
followed by an explicit acceptance sentence:

    /usr/bin/csrutil status | /usr/bin/grep -c '...enabled.'

    If the result is not "1", this is a finding.

A deterministic extractor recovers the command and the expected value from
that structure exactly, with no risk of invention. Using a language model
where a parser suffices would add hallucination risk and buy nothing.

So the model's role is scoped to the residue: rules whose check text has no
acceptance sentence, encodes a GUI procedure, or resists reduction to a
single command. Those are emitted as ``low`` confidence for a human, and
``stigscan author --ai-assist`` can ask a model to propose a reading of them.
Every entry — extractor-authored or model-authored — lands as UNREVIEWED.
"""

from __future__ import annotations

import re

from .pack import Check, CheckPack, MODE_SHELL, MODE_MANUAL, MODE_UNSUPPORTED
from .safety import audit
from . import platforms

EXTRACTOR_ID = "rule-based-extractor/1.0"

# "If the result is not "1", this is a finding."  -> equals "1"
_NEGATIVE = re.compile(
    r"If the (?:result|output|value|return)[^.\n]*?\bis not\b\s*[\"']?([^\"'\n,]*?)[\"']?\s*,?\s*this is a finding",
    re.I)
# "If the result is "0", this is a finding."      -> not_equals "0"
_POSITIVE = re.compile(
    r"If the (?:result|output|value|return)[^.\n]*?\bis\b\s*[\"']([^\"'\n]*?)[\"']\s*,?\s*this is a finding",
    re.I)
_ANY_FINDING = re.compile(r"^.*this is a finding.*$", re.I | re.M)
_CMD_ANCHOR = re.compile(r"^.*?\bcommands?\b\s*:\s*$", re.I | re.M)
_GUI_HINT = re.compile(
    r"\b(click|System Settings|System Preferences|menu bar|top left corner|"
    r"interview the|ask the|verify with the (?:SA|ISSO)|documented with the ISSO)\b", re.I)
_NOTE_TAIL = re.compile(r"^\s*(note|warning)\s*:", re.I | re.M)


_SUDO = re.compile(r"(?:/usr/bin/)?(?<![\w-])sudo\s+", re.I)
_SUDO_AS_USER = re.compile(r"(?:/usr/bin/)?\bsudo\s+-u\b", re.I)


def _strip_sudo(command: str) -> tuple[str, bool]:
    """Remove in-command privilege escalation, declaring it instead.

    A check that embeds `sudo` prompts for a password mid-scan and hides its
    own privilege requirement. The pack models this explicitly: the command
    is stored unprivileged and `requires_root` is set, so the operator is
    told up front that this check needs `sudo stigscan scan`.
    """
    if _SUDO_AS_USER.search(command):
        # `sudo -u <user>` runs as a *specific* user, not root. Rewriting that
        # away would silently change what the check measures, so it is left
        # intact for a human to decide.
        return command, False
    if not _SUDO.search(command):
        return command, False
    return _SUDO.sub("", command), True


def _extract_command(check_text: str, prof=platforms.macos) -> str:
    """Recover the shell snippet between the prose anchor and the verdict line."""
    anchors = list(_CMD_ANCHOR.finditer(check_text))
    start = anchors[-1].end() if anchors else 0

    body = check_text[start:]
    verdict = _ANY_FINDING.search(body)
    if verdict:
        body = body[: verdict.start()]
    note = _NOTE_TAIL.search(body)
    if note:
        body = body[: note.start()]
    return prof.clean_command(body)


def _expected(check_text: str) -> tuple[str, str, str] | None:
    """Return (comparator, expected, verbatim source sentence)."""
    m = _NEGATIVE.search(check_text)
    if m:
        return ("equals", m.group(1).strip(), m.group(0).strip())
    m = _POSITIVE.search(check_text)
    if m:
        return ("not_equals", m.group(1).strip(), m.group(0).strip())
    return None


def candidate_from_rule(rule: dict, authored_at: str, platform: str | None = None) -> Check:
    prof = platforms.get(platform)
    check_text = rule.get("check_text", "") or ""
    chk = Check(
        stig_id=rule.get("stig_id", ""),
        group_id=rule.get("group_id", ""),
        severity=rule.get("severity", "medium"),
        title=rule.get("title", ""),
        authored_by=EXTRACTOR_ID,
        authored_at=authored_at,
    )

    # A platform without an extractor: say so, per rule, rather than guess.
    if not prof.EXTRACTOR:
        chk.mode = MODE_UNSUPPORTED
        chk.manual_instruction = check_text.strip()
        chk.author_confidence = "low"
        chk.author_note = (f"no extractor for platform {prof.NAME!r} in this release "
                           "— needs human or AI authoring")
        return chk

    exp = _expected(check_text)
    command = _extract_command(check_text, prof)
    prof_conf = None
    prof_note = ""
    if exp is None and hasattr(prof, "expected"):
        body = check_text
        anchors = list(_CMD_ANCHOR.finditer(check_text))
        if anchors:
            body = check_text[anchors[-1].end():]
        got = prof.expected(check_text, body)
        if got:
            comparator, expected, source, prof_conf, prof_note = got
            exp = (comparator, expected, source)

    # A GUI/interview procedure is not automatable, and saying so is the
    # correct answer rather than a failure of the extractor.
    if (prof.GUI_HINT.search(check_text) or _GUI_HINT.search(check_text)) and not command:
        chk.mode = MODE_MANUAL
        chk.manual_instruction = check_text.strip()
        chk.author_confidence = "high"
        chk.author_note = "check text describes a GUI or interview procedure"
        return chk

    if not command or exp is None:
        chk.mode = MODE_UNSUPPORTED
        chk.manual_instruction = check_text.strip()
        chk.author_confidence = "low"
        missing = []
        if not command:
            missing.append("no command block found")
        if exp is None:
            missing.append("no explicit acceptance sentence")
        chk.author_note = "; ".join(missing) + " — needs human or AI authoring"
        return chk

    comparator, expected, source = exp
    command, needs_root = _strip_sudo(command)
    chk.mode = MODE_SHELL
    chk.command = command
    chk.requires_root = needs_root
    chk.comparator = comparator
    chk.expected = expected
    chk.expected_source = source

    problems = audit(command, prof.NAME)
    if problems:
        chk.author_confidence = "low"
        chk.author_note = "safety gate objections: " + "; ".join(problems)
    elif "\n" in command:
        chk.author_confidence = "medium"
        chk.author_note = "multi-line snippet — confirm it is self-contained"
    else:
        chk.author_confidence = "high"
    if prof_conf:
        order = {"high": 0, "medium": 1, "low": 2}
        if order[prof_conf] > order[chk.author_confidence]:
            chk.author_confidence = prof_conf
        if prof_note:
            chk.author_note = (chk.author_note + "; " if chk.author_note else "") + prof_note

    if re.search(r"\b(as root|administrator privileges required)\b", check_text, re.I):
        chk.requires_root = True
    return chk


def _version_label(checklist: dict) -> str:
    """Render DISA's split version/release fields as the familiar V1R3 form."""
    version = str(checklist.get("version", "")).strip()
    release_info = str(checklist.get("release_info", "")).strip()
    m = re.search(r"Release:\s*(\d+)", release_info)
    if version and m:
        return f"V{version}R{m.group(1)}"
    return release_info or version


def build_pack(checklist: dict, pack_id: str, authored_at: str,
               only: set[str] | None = None, platform: str | None = None) -> CheckPack:
    prof = platforms.get(platform)
    rules = checklist.get("rules", [])
    if only:
        rules = [r for r in rules if r.get("stig_id") in only]
    pack = CheckPack(
        pack_id=pack_id,
        stig_title=checklist.get("title", ""),
        stig_version=_version_label(checklist),
        created=authored_at,
        notes=("Candidate checks derived from DISA check text. Every entry is "
               "UNREVIEWED until a human approves it; approval freezes the "
               "entry's content digest."),
        platform=prof.NAME,
        checks=[candidate_from_rule(r, authored_at, prof.NAME) for r in rules],
    )
    return pack

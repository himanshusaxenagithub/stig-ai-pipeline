"""XCCDF parser for DISA STIG files.

Reads a DISA STIG package (.zip) or a raw XCCDF XML file and produces a
list of Rule objects. Namespace-agnostic so it works with XCCDF 1.1
(what DISA ships) as well as XCCDF 1.2.
"""

from __future__ import annotations

import html
import io
import re
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from xml.etree import ElementTree as ET


@dataclass
class Rule:
    stig_id: str            # e.g. APPL-15-000002 (from <version>)
    group_id: str           # e.g. V-268421
    rule_id: str            # e.g. SV-268421r... (Rule @id)
    severity: str           # high / medium / low
    title: str
    discussion: str
    check_text: str
    fix_text: str
    ccis: list = field(default_factory=list)
    srgs: list = field(default_factory=list)
    # Filled by the AI layer (optional)
    ai: dict = field(default_factory=dict)

    @property
    def cat(self) -> str:
        return {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}.get(
            self.severity, "?"
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cat"] = self.cat
        return d


@dataclass
class Benchmark:
    title: str
    version: str
    release_info: str
    source_file: str
    rules: list

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "version": self.version,
            "release_info": self.release_info,
            "source_file": self.source_file,
            "rule_count": len(self.rules),
            "rules": [r.to_dict() for r in self.rules],
        }


def _local(tag: str) -> str:
    """Strip an XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


def _find(elem, name):
    for child in elem.iter():
        if _local(child.tag) == name:
            return child
    return None


def _findall_direct(elem, name):
    return [c for c in list(elem) if _local(c.tag) == name]


def _text(elem) -> str:
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip()


_VULN_DISCUSSION = re.compile(
    r"<VulnDiscussion>(.*?)</VulnDiscussion>", re.DOTALL | re.IGNORECASE
)


def _extract_discussion(description: str) -> str:
    """DISA embeds escaped pseudo-XML inside <description>. Pull out the
    human-readable VulnDiscussion portion; fall back to the raw text."""
    if not description:
        return ""
    unescaped = html.unescape(description)
    m = _VULN_DISCUSSION.search(unescaped)
    text = m.group(1) if m else unescaped
    # Drop any other pseudo-tags that remain (FalsePositives, Mitigations, ...)
    text = re.sub(r"</?[A-Za-z][^>]*>", "", text)
    return text.strip()


def _parse_group(group) -> Rule | None:
    rule = None
    for child in list(group):
        if _local(child.tag) == "Rule":
            rule = child
            break
    if rule is None:
        return None

    version_el = _findall_direct(rule, "version")
    title_el = _findall_direct(rule, "title")
    desc_el = _findall_direct(rule, "description")
    fix_el = _findall_direct(rule, "fixtext")

    check_text = ""
    for check in _findall_direct(rule, "check"):
        cc = _find(check, "check-content")
        if cc is not None:
            check_text = _text(cc)
            break

    ccis, srgs = [], []
    for ident in _findall_direct(rule, "ident"):
        val = (ident.text or "").strip()
        if val.startswith("CCI-"):
            ccis.append(val)
    gtitle = _findall_direct(group, "title")
    if gtitle and (gtitle[0].text or "").startswith("SRG-"):
        srgs.append(gtitle[0].text.strip())

    return Rule(
        stig_id=_text(version_el[0]) if version_el else "",
        group_id=group.get("id", ""),
        rule_id=rule.get("id", ""),
        severity=rule.get("severity", "unknown").lower(),
        title=_text(title_el[0]) if title_el else "",
        discussion=_extract_discussion(
            (desc_el[0].text or "") if desc_el else ""
        ),
        check_text=check_text,
        fix_text=_text(fix_el[0]) if fix_el else "",
        ccis=ccis,
        srgs=srgs,
    )


def _read_xccdf_bytes(path: Path) -> tuple:
    """Return (xml_bytes, source_name). Accepts .xml or a DISA .zip
    (picks the *-xccdf.xml inside, searching nested zips one level deep)."""
    if path.suffix.lower() != ".zip":
        return path.read_bytes(), path.name

    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        xccdf = [n for n in names if n.lower().endswith("xccdf.xml")]
        if xccdf:
            return z.read(xccdf[0]), xccdf[0]
        # DISA sometimes nests a zip inside the zip
        for n in names:
            if n.lower().endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(z.read(n))) as inner:
                    inner_xccdf = [
                        m for m in inner.namelist()
                        if m.lower().endswith("xccdf.xml")
                    ]
                    if inner_xccdf:
                        return inner.read(inner_xccdf[0]), inner_xccdf[0]
    raise FileNotFoundError(
        f"No *-xccdf.xml found inside {path.name}. "
        "Is this a DISA STIG package?"
    )


def parse_stig(path) -> Benchmark:
    path = Path(path)
    xml_bytes, source = _read_xccdf_bytes(path)
    root = ET.fromstring(xml_bytes)

    if _local(root.tag) != "Benchmark":
        bench = _find(root, "Benchmark")
        if bench is None:
            raise ValueError(f"{source}: not an XCCDF Benchmark document")
        root = bench

    title = ""
    version = ""
    release_info = ""
    for child in list(root):
        name = _local(child.tag)
        if name == "title" and not title:
            title = _text(child)
        elif name == "version" and not version:
            version = _text(child)
        elif name == "plain-text" and child.get("id") == "release-info":
            release_info = _text(child)

    rules = []
    for child in root.iter():
        if _local(child.tag) == "Group":
            parsed = _parse_group(child)
            if parsed:
                rules.append(parsed)

    order = {"high": 0, "medium": 1, "low": 2}
    rules.sort(key=lambda r: (order.get(r.severity, 3), r.stig_id))
    return Benchmark(
        title=title, version=version, release_info=release_info,
        source_file=source, rules=rules,
    )

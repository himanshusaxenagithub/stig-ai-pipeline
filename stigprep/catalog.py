"""Fetch an official DISA STIG package, so nobody has to go and find it.

The hardest step in using this project was never the software. It was
"go to public.cyber.mil, work out which of several hundred packages you
need, download it, unzip it." This module removes that step.

    python3 -m stigprep fetch windows-11
    python3 -m stigprep fetch --list

Three things it does on purpose:

* it is a separate command, so ``parse`` never reaches out to the network
  on its own. Nothing here runs unless a person asks for it;
* it verifies what it downloaded. If the catalogue records a SHA-256 the
  file must match it. Either way the observed digest is printed, and the
  archive must contain an XCCDF document with the expected number of
  rules before the download is accepted;
* when the network refuses — a school or corporate filter, an air-gapped
  network, a proxy — it prints the exact address and stops, rather than
  failing with a stack trace.

DISA reissues these guides roughly quarterly and the release number is in
the filename, so each entry records the release this project has validated.
That release is tried first, because the explanations and check packs
shipped here were built against it; newer and then older releases are tried
only if it has been withdrawn, and the difference is reported. When every
candidate fails, the message says to check the published download page.

No third-party dependencies.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"
DOWNLOAD_PAGE = "https://public.cyber.mil/stigs/downloads/"
USER_AGENT = "stig-ai-pipeline (+https://github.com/himanshusaxenagithub/stig-ai-pipeline)"


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Guide:
    key: str
    label: str
    platform: str                 # macos | windows | linux | database
    template: str                 # filename, with {rel} for the release number
    release: int                  # the release this project has validated
    rules: int | None = None      # expected rule count, when the package holds one guide
    sha256: str | None = None     # pinned digest of that release, when recorded
    lookahead: int = 6            # how many newer releases to try first
    desktop: bool = False         # offered in the page; everything else is CLI only

    def candidates(self) -> list[tuple[int, str]]:
        """(release, filename) to try, in order.

        The validated release comes first on purpose. This project ships
        explanations and check packs built against it, so reaching for a
        newer release by default would hand someone a guide whose filed
        explanations do not attach. Newer releases are tried only if DISA
        has withdrawn the validated one, and older ones after that.
        """
        order = [self.release]
        order += [self.release + n for n in range(1, self.lookahead + 1)]
        order += [rel for rel in range(self.release - 1, 0, -1)]
        return [(rel, self.template.format(rel=rel)) for rel in order]

    def url(self, filename: str) -> str:
        return f"{BASE}/{filename}"


CATALOG: list[Guide] = [
    Guide("macos-26", "MacBook — macOS 26 (Tahoe)", "macos",
          "U_Apple_macOS_26_V1R{rel}_STIG.zip", release=3, rules=160, desktop=True),
    Guide("macos-15", "MacBook — macOS 15 (Sequoia)", "macos",
          "U_Apple_macOS_15_V1R{rel}_STIG.zip", release=7, desktop=True),
    Guide("windows-11", "Windows 11 PC", "windows",
          "U_MS_Windows_11_V2R{rel}_STIG.zip", release=9, rules=257, desktop=True),
    Guide("windows-server-2019", "Windows Server 2019", "windows",
          "U_MS_Windows_Server_2019_V3R{rel}_STIG.zip", release=8, rules=282),
    Guide("ubuntu-24.04", "Canonical Ubuntu 24.04 LTS", "linux",
          "U_CAN_Ubuntu_24-04_LTS_V1R{rel}_STIG.zip", release=6, rules=194),
    Guide("rhel-9", "Red Hat Enterprise Linux 9", "linux",
          "U_RHEL_9_V2R{rel}_STIG.zip", release=9, rules=445),
    Guide("sql-server-2022", "Microsoft SQL Server 2022", "database",
          "U_MS_SQL_Server_2022_Y26M0{rel}_STIG.zip", release=4, lookahead=2),
]

BY_KEY = {g.key: g for g in CATALOG}


def desktop_guides() -> list[Guide]:
    """The guides the page offers.

    The page exists for the two machines a small organisation actually has
    on desks: a MacBook and a Windows PC. Servers, Linux and databases are
    real work for a technical person, who is better served by the command
    line than by a wizard, so they stay in ``stigprep fetch``.
    """
    return [g for g in CATALOG if g.desktop]


def cli_only_guides() -> list[Guide]:
    return [g for g in CATALOG if not g.desktop]


def for_platform(platform: str) -> list[Guide]:
    return [g for g in CATALOG if g.platform == platform]


def recommended(platform_name: str | None = None) -> str | None:
    """The guide key for the computer this is running on.

    A MacBook owner should not have to know whether they are on Tahoe or
    Sequoia, so the macOS major version decides. Anything else falls back to
    the first guide published for that platform.
    """
    import platform as _p
    name = platform_name or {"Darwin": "macos", "Windows": "windows",
                             "Linux": "linux"}.get(_p.system(), "")
    if name == "macos":
        major = (_p.mac_ver()[0] or "").split(".")[0]
        return "macos-15" if major == "15" else "macos-26"
    if name == "windows":
        return "windows-11"
    guides = for_platform(name)
    return guides[0].key if guides else None


# ------------------------------------------------------------------ io ----

def _get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _rule_count(data: bytes) -> int:
    """Rules in the first XCCDF document of the archive, 0 if there is none."""
    import io
    import re
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = [n for n in zf.namelist()
                       if n.lower().endswith(".xml") and "xccdf" in n.lower()]
            if not members:
                return 0
            text = zf.read(members[0]).decode("utf-8", "replace")
    except (zipfile.BadZipFile, OSError):
        return 0
    return len(re.findall(r"<(?:\w+:)?Rule\b", text))


def fetch(key: str, dest_dir: Path | str = ".", *, progress=print) -> Path:
    """Download *key* into *dest_dir* and return the path written.

    Raises FetchError with an address a person can use by hand when the
    download cannot be completed or the file does not look right.
    """
    guide = BY_KEY.get(key)
    if guide is None:
        raise FetchError(f"unknown guide {key!r}; try: " + ", ".join(sorted(BY_KEY)))

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    tried: list[str] = []
    for release, filename in guide.candidates():
        url = guide.url(filename)
        tried.append(url)
        try:
            progress(f"  trying {filename}")
            data = _get(url)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                continue
            if release != guide.release:
                continue
            raise FetchError(
                f"could not reach {BASE}: {e}. Download it by hand from "
                f"{DOWNLOAD_PAGE} (search for {guide.label!r}) and open the file here."
            ) from e

        digest = hashlib.sha256(data).hexdigest()
        if guide.sha256 and digest != guide.sha256:
            raise FetchError(
                f"{filename} does not match the digest recorded for release "
                f"{guide.release}: expected {guide.sha256}, got {digest}. "
                "Refusing to use it."
            )

        found = _rule_count(data)
        if found == 0:
            raise FetchError(f"{filename} contains no XCCDF document; refusing to use it.")
        if guide.rules and release == guide.release and found != guide.rules:
            raise FetchError(
                f"{filename} holds {found} rules; release {guide.release} of "
                f"{guide.label} should hold {guide.rules}. Refusing to use it."
            )

        target = dest_dir / filename
        target.write_bytes(data)
        progress(f"  downloaded {filename}  ({len(data):,} bytes, {found} rules)")
        progress(f"  sha256 {digest}")
        if release != guide.release:
            progress(f"  note: release {guide.release} is the one validated here and it was "
                     f"not available, so this is release {release}. The filed explanations "
                     "and check packs may not match it.")
        return target

    raise FetchError(
        f"no published release of {guide.label} was found under {BASE}. "
        f"DISA may have renamed it; check {DOWNLOAD_PAGE} and open the file here. "
        f"Tried {len(tried)} addresses."
    )

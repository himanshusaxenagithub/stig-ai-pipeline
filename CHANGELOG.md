# Changelog

## v0.7.2 — 2026-09-13

### Added — contact, moderated reviews, GoatCounter activity

- Pages footers list Contact: `1992.hsaxena@gmail.com`, plus optional
  [hsaxena.com](https://hsaxena.com) and [writing](https://hsaxena.com/writing).
- `docs/reviews.html` is a FormSubmit form (required name, email, review;
  optional organisation). Subject: `STIG site review submission`. First use
  needs the FormSubmit activation email. Approved reviews live in
  `docs/data/reviews.json` (starts empty; no email field). Copy states that
  reviews appear only after manual approval and emails are never published.
- `docs/used.html` stays as the optional public-note path and points at Reviews.
- GoatCounter: `docs/site-config.js` holds `goatcounterCode`
  (`YOUR_GOATCOUNTER_CODE` until a real site is created). `docs/site-chrome.js`
  adds the count script and fills the landing **Site activity** block from
  the public ` /counter/TOTAL.json` endpoint. Placeholder or failed fetch
  shows `—`, not invented numbers. These are website visits, not DoD adoption.

## v0.7.1 — 2026-09-13

### Added — stig-harden (module 4)

- `python3 -m stigharden`: draft platform-appropriate remediation
  scripts from scan failures (Windows registry / auditpol, macOS
  defaults / launchctl, Linux sysctl). High-risk forms stay manual.
  Approval freezes a digest; it does not apply the script.
- `apply` is a dry-run unless `--apply-for-real` is passed. That flag
  is refused in CI and still requires `--by` and `--i-have-reviewed`.
- `skills/stig-harden/` drives the same flow. The helper rejects
  batches that set apply state or file a high-risk script.
- stigui: **Draft POA&M entries** and **Draft fixes** after a scan.
  The page never closes a finding and never applies a change.
- Tests and fixtures under `tests/fixtures/harden/`.

## v0.7.0 — 2026-09-13

### Added — stig-assess (module 3)

- `python3 -m stigassess`: draft POA&M-style entries from a stig-scan
  JSON report. Default input is scan failures only; passing results are
  refused. Evaluation gaps and manual inspections are opt-in and are
  labelled as gaps, not findings.
- Approval freezes a SHA-256 digest over the wording a named person
  read and moves the item from draft to open. It does not close the
  finding. `close` is a separate command that requires a name, a kind
  (`remediated`, `risk_accepted`, `not_applicable`), and a note.
- `skills/stig-assess/` drives the same flow. The helper rejects any
  batch that would mark an item complete or invent a command.
- Tests and fixtures under `tests/fixtures/assess/`.

## v0.6.9 — 2026-09-13

### Added — evidence and transparency pages

- `docs/evidence.html` is a dated public record: MIT licence, no API key,
  human approval before any check runs, macOS / Linux / Windows, how to
  reproduce a CAT I scan, and links to the start-page demo (and to
  `demo.html` / `articles/` when those files are on the site).
- A “what we do not claim” section states there is no DoD or DISA
  endorsement, that stars are not adoption, and that sample demo data is
  labeled. No usage metrics are invented.
- `docs/used.html` invites an optional public note via
  `mailto:1992.hsaxena@gmail.com` or a GitHub issue template. No
  testimonials are written on the page.
- The start-page footer adds a quiet **For reviewers / transparency** link.

## v0.6.8 — 2026-09-13

### Added — example run on the product site

- `docs/demo.html` is a static, article-style walk-through of pick OS →
  CAT I select → download → approve → remaining-risk results. Figures are
  SVG illustrations with invented clinic data, labeled as example. The
  start page links it from the hero, the step tabs, a short “see an
  example first” block, and the footer.
- Longer essays belong on the personal site
  ([hsaxena.com](https://hsaxena.com)), not on this product Pages site.
  The start page has one outbound pointer, not an essay library.
- Landing copy attributes STIGs to DISA / the Department of Defense.
  It does not say “the Pentagon publishes.”

## v0.6.7 — 2026-09-13

### Changed — DoD-plain landing wording

- Hero and meta now say the US Department of Defense publishes free STIG
  checklists, and that this site explains them and helps you check your PC.
- Dropped “Pentagon”, “most people never apply them”, and unattributed
  “most thorough” claims. The beginner demo from v0.6.6 stays in place.

## v0.6.6 — 2026-09-13

### Added — beginner demo on the start page

- The GitHub Pages start step now has a **Demo — try a simple first scan**
  block: DoD publishes free STIG checklists; this tool lists configuration
  gaps on your Mac or Windows PC; today it finds misses (report/PDF), and
  guided fixes may come later. First demo: CAT I only.
- Mac / Windows demo buttons open the rules list with the CAT I filter on
  and a one-click **Select CAT I for demo**. Nothing downloads until the
  person asks. Technical DISA/CORS notes stay collapsed.

## v0.6.5 — 2026-09-13

### Changed — less repetition on the start page

- “What is a STIG?” is one short definition plus the three-panel diagram.
  The extra three cards and the caption that restated the same steps are gone.
- “What this tool does” is product actions only (pick, select, download,
  approve, report). The separate “How it works” section is folded into that.

## v0.6.4 — 2026-09-13

### Changed — layman-friendly start page

- The GitHub Pages start step now leads with why STIGs matter, a short
  “what is a STIG” explainer with diagrams, what the tool does, and a
  five-step process. MacBook / Windows pick is unchanged and still starts
  the download flow.
- CORS, `dl.dod.cyber.mil`, SHA-256 and `stigprep fetch` notes move into
  a collapsed Technical notes block (and a footer link). The catalogue
  note is no longer written into the landing status line.

## v0.6.3 — 2026-09-13

### Added — plain-language scan results

- After a local scan, stigui shows a remaining-risk headline (Low /
  Moderate / High / Critical, or Incomplete when nothing was judged),
  SVG charts for pass/fail, fails-by-severity, and coverage, and a
  callout that points at the failing rules. Coverage is still stated
  first: this is not a fake “percent secure.”
- PDF and Markdown reports add a short “What this means” section with
  ASCII bars so the downloaded file matches the friendlier story.
  Existing coverage-first tests stay green.

## v0.6.2 — 2026-09-13

### Fixed

- The rules page no longer pre-ticks every machine check. Selection starts
  empty; Select shown / CAT I / machine-check still fill it explicitly, and
  download still requires at least one rule.
- The site fetches `packages/scanner-src.zip?v=<payload sha256>` with
  `cache: "no-store"` so a browser that cached the pre-`Dim args` zip cannot
  keep serving it after a Pages deploy. Delete the old unzipped folder before
  unpacking a new download.

## v0.6.1 — 2026-09-13

### Fixed

- `run-hidden.vbs` declared `args` under `Option Explicit`. Without `Dim args`
  Windows Script Host stopped at line 51 (`800A01F4`) when someone double-clicked
  the website's STIG-Scanner-Windows zip. Selection.json is still passed through
  when present.

## v0.6.0 — 2026-09-13

### Added — public website and a configured local scanner

- GitHub Pages site under `docs/`: pick MacBook or Windows, read the filed
  explanations, select rules, download an OS-specific scanner zip already
  pointed at that selection. Static HTML/JS only — no API key, no remote
  host scan. Expected URL:
  `https://stig.hsaxena.com`
- The site ships catalogue metadata (validated release, rule count, SHA-256
  when pinned) because Pages cannot fetch `dl.dod.cyber.mil`. The local
  program still downloads the official zip and refuses a mismatch.
- `packaging/build_site.py` exports `docs/data/` and `docs/packages/scanner-src.zip`.
- `packaging/build_scanpack.py` builds the same configured folder from the CLI.
- `stigui --selection` / `--pack` open a website pack; `selection.json` next
  to Start.command is picked up automatically. Checks stay unreviewed until
  a person types their name.
- PDF scan reports (`stigscan/pdf.py`), written beside the JSON and Markdown
  by both `stig-scan scan` and the local page. Standard library only.
- `.github/workflows/pages.yml` deploys `docs/` when Pages is set to GitHub
  Actions. Branch-folder `/docs` also works with the committed files.

## v0.5.0 — 2026-09-11

### Added — a page instead of a terminal

- `stigui`: a local web interface covering the whole method — choose a guide,
  read the rules in plain English, read and approve each check under your own
  name, scan, read the report, download the outputs. Standard library only.
  Served on `127.0.0.1`, guarded by a one-time token and a loopback-only Host
  check, so no other page or process on the machine can drive it.
- `Start.command` (macOS) and `Start.bat` (Windows): double-click to open it.
- `Start.command` / `Start.bat` (for a plain source checkout, using whatever
  Python is already on the machine) now start in the same app mode as the
  packaged program: Quit button, single running instance, files in the
  per-user application folder. Windows gets `run-hidden.vbs`, so no black
  console window flashes on screen; missing Python is a dialog box on both
  platforms, pointing at python.org, not text in a terminal someone might
  not read.
- `.github/workflows/release-portable.yml`: builds and attaches
  STIG-Checker-macOS.zip / STIG-Checker-Windows.zip to a GitHub Release
  automatically, so a release does not depend on running Build.command by
  hand on two different computers. Reviewed against the actual build
  script's flags and syntax-checked; not yet exercised by an actual
  release — the first real release should be watched.
- **STIG Checker**, the double-click program: on a Mac a real application bundle
  with its own icon, on Windows `STIG Checker.bat` beside a `program` folder.
  Started from the desktop it runs in *app mode* — files in the per-user
  application folder, a second double-click reopens the page instead of starting
  a second copy, a Quit button and a Show files button on the page, and it stops
  itself once nobody has had the page open for ten minutes. The command line is
  unchanged. `Build.command` / `Build.bat` produce it, and `Read me.txt` beside it
  gives the exact first-open steps for an unsigned program on macOS 15+, older
  macOS and Windows. `--sign` / `--notarize` are there for when there is an
  Apple Developer ID, and are marked as not yet exercised.
- `packaging/build_portable.py`: assembles a folder that carries its own
  Python, so someone with no Python and no administrator rights can unzip it
  and double-click. Run once per platform. Nothing is packed or compiled —
  the code ships as the same .py files that are on GitHub, which keeps the
  "read exactly what this runs" argument intact and avoids the antivirus
  false positives that packers attract. No source change was needed: the
  folder has the same shape as a checkout, so annotations, check packs and
  the page are found the same way.
- `stigprep fetch`: download the official DISA package by name, so nobody has to
  find it on public.cyber.mil and unzip it. The page leads with the two machines
  this is for — MacBook and Windows PC — and picks the right macOS release from
  the version actually running, so nobody has to know whether they are on Tahoe
  or Sequoia. The page offers those two machines only, and refuses a request for
  any other guide with the command to use instead — servers, Linux and databases
  are for someone who administers systems for a living, and the command line
  serves that person better than a wizard does. Verified against a pinned digest where one is
  recorded and always against the validated rule count; the validated release is
  tried first so the filed explanations attach; a blocked network prints the
  download page rather than a stack trace.
- A shipped check pack is copied into the work folder the first time it is
  opened, so a person's approvals survive `git pull` and the packs published
  here stay unreviewed as documented.
- README: a Windows first-run section covering the PATH checkbox, the need for
  a fresh shell, and the nested folder that Windows creates when unpacking a ZIP.

### Fixed

- The Checks screen no longer labels GUI and interview rules as
  "unreviewed" with a disabled checkbox. Those rules have no command, so
  they cannot be approved or executed — on Windows 11 that is 103 of 257.
  They now read "needs a person" or "no command", with a note and a button
  that takes you to scan the checks that will actually run.

- Scan progress is now visible while a scan is running. The page used to sit
  on "running…" until every check had finished, which on Windows — where the
  PowerShell window is hidden and a STIG has a couple of hundred checks —
  looked like nothing was happening. Each check now streams to the page as it
  starts and as it returns, and the command line prints the same, flushed so
  a Windows console cannot hold the lines until the end.

- `--explain` found no filed explanations when it was handed a DISA `.zip`
  rather than the XCCDF inside it, because filed sets are named after the XCCDF.
  The lookup now tries the source name, then each XCCDF member of the archive,
  and finally the filed set sharing the most rule identifiers with the
  benchmark — so a renamed release still finds its explanations. The command
  documented in the README (`parse <stig>.zip --explain`) works as written.


## v0.4.0 — 2026-09-09

### Added — Windows scanning

- `stigscan/platforms/windows.py` now carries an extractor. DISA writes
  Windows check text as structured descriptions rather than commands; four
  regular shapes are mapped to read-only PowerShell: registry
  hive/path/value → `Get-ItemProperty`; `AuditPol` plus a subcategory line
  → `auditpol /get /subcategory /r`; a gpedit path with a `Secedit /Export`
  fallback → `secedit /export` to a scratch file and one key read; a quoted
  read-only cmdlet with an acceptance sentence → that cmdlet. GUI-only
  procedures are MANUAL; the rest stay UNSUPPORTED for a human.
- Authored packs: `checkpacks/windows-11-v2r9.json` (257 rules, 154
  reducible, 15 manual), `checkpacks/windows-server-2019-v3r8.json` (282,
  160 reducible, 23 manual). Both entirely unreviewed, by design.
- `skills/stig-scan-windows/` — the scanning skill for Windows, replacing
  the placeholder.
- Windows safety gate: `Remove-Item` is permitted only as
  `Remove-Item $f -Force` on the secedit scratch file; every other form is
  refused.
- 8 new tests (84 total).

## v0.3.0 — 2026-09-06

### Added — platform profiles for `stig-scan`

- `stigscan/platforms/` — one module per operating system carrying what
  actually differs: the read-only binary allowlist, the forbidden mutating
  forms, the shell, and how DISA writes check text for that platform. The
  scanner core (packs, review, approval digests, safety gate, runner,
  report) is unchanged and platform-neutral.
- `macos` — the reference profile; the previous allowlist, unchanged.
- `linux` — Ubuntu / RHEL family. Allowlist of ~110 read-only tools, a
  forbidden list covering `systemctl`, `sysctl -w`, `ufw`, `auditctl -w`,
  package managers, account and firewall changes, boot configuration.
  Extractor handles DISA's prompt-line-plus-sample-output check text and
  maps the unambiguous acceptance sentences; the rest stay UNSUPPORTED.
  Authored packs: `checkpacks/ubuntu-24.04-v1r6.json` (72 of 194 rules
  reducible), `checkpacks/rhel-9-v2r9.json` (156 of 445). Both ship
  entirely unreviewed, by design.
- `windows` — safety vocabulary only (read-only cmdlets, mutating forms).
  No extractor: `author` marks every rule UNSUPPORTED with a note; `scan`
  refuses a Windows pack.
- Packs record `platform`; `scan` refuses to run a pack on a different
  platform than it declares. Legacy packs without the field load as macOS.
- `stigscan author --platform {macos,linux,windows}` (default: the host).
- 16 new tests (77 total).

### Added — skills

- `skills/stig-explain/` — plain-English explanations:
  the assistant writes summary / triage / automation / caution for ten
  rules at a time; a helper validates and files them into the checklist
  and `annotations/`, which `--explain` also reads.
- `skills/stig-scan-macos/`, `skills/stig-scan-linux/` — drive Module 2
  end to end; the assistant reads, explains and reports, the human
  approves, the scanner runs only approved checks.
- `skills/stig-scan-windows/` — states plainly that Windows scanning is not
  yet supported and what to do instead.
- `annotations/` — complete explanation sets for seven STIGs, 1,440 rules,
  produced with the skill: Windows 11 V2R9, Windows Server 2019 V3R8,
  RHEL 9 V2R9, Ubuntu 24.04 V1R6, macOS 26 V1R3, SQL Server 2022 Instance
  V1R4 and Database V1R3.

### Removed

- The direct API annotation path and `--model`. Explanations are produced
  with the stig-explain skill and committed; the parser attaches them.

### Changed

- `not_equals` with empty output is now ERROR ("no output to evaluate"),
  not PASS. "Anything but X" is only evidence if there was an answer.
- `make_tracker.py` adds four explanation columns when annotations exist.
- `--explain` now only attaches filed explanations (repository `annotations/` and a local cache). No network calls, no account, no key anywhere in the tool.
- stig-to-tracker plausibility ceiling raised to 500 rules (RHEL 9 V2R9
  carries 445).

## v0.2.0 — 2026-08-20

### Added — module 2, `stig-scan`

- `stigscan author` derives candidate checks from a stig-prep checklist by
  parsing DISA check text. On the macOS 26 V1R3 STIG this reduces 153 of 160
  rules to an executable command and an explicit acceptance criterion.
- Human review gate: `review`, `approve`, `reject`, `verify`. Approval freezes
  a SHA-256 digest over the executable content of a check; post-approval edits
  are detected as drift and refused at scan time.
- Static safety gate — read-only binary allowlist plus a forbidden-construct
  denylist — enforced in the orchestrator, so a check judged unsafe is
  reported as `error` rather than as a compliance verdict, regardless of
  runner.
- `stigscan scan` produces JSON (for module 3) and Markdown (for humans),
  both leading with an explicit statement of how many rules actually produced
  evidence.
- Recorded-fixture runner: `--record` captures a scan as a durable artifact,
  `--fixtures` replays it on any platform, including CI hosts that cannot run
  macOS commands.
- `checkpacks/macos-26-v1r3.json` — 160 candidate checks for Apple macOS 26
  (Tahoe) V1R3, shipped entirely unreviewed by design.
- `docs/REVIEW_WORKFLOW.md`.
- 50 new tests (61 total).

### Notes

Building the authoring step produced a finding worth recording: the macOS
STIG check text is structured enough that a deterministic parser recovers the
command and expected value for 95.6% of rules exactly. A language model was
not used for that bulk, because a parser cannot hallucinate and the model
would have added risk without adding capability. The model's role is scoped
to the residue — the rules with no machine-readable acceptance criterion.

## v0.1.0 — 2026-08-04

- Module 1, `stig-prep`: parse any DISA STIG (XCCDF) into Markdown / JSON /
  CSV checklists, with optional AI triage and plain-English explanations.
- `skills/stig-to-tracker/`: AI skill packaging the parse-to-Excel workflow.

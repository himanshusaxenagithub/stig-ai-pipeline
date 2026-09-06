---
name: stig-scan-linux
description: Check a Linux server (Ubuntu, RHEL and family) against its DISA STIG and report, in plain English, where it stands. Use this skill whenever the user asks to scan, audit, assess or check a Linux system against a STIG, mentions Ubuntu or RHEL compliance, a checkpack, or says anything like "scan this server", "run the STIG checks on this box", "how compliant is this VM" — even if they do not name the tool. It drives stig-scan (Module 2) on the Linux profile, never approves a check on the user's behalf, and never runs anything a human has not approved.
---

# Scan a Linux system against its STIG

Same procedure as stig-scan-macos — locate → author → verify → review → the
human approves → scan → explain — with the Linux profile. Read that skill
for the full step text; this file carries only what is different on Linux.

The guiding principle is unchanged: **nothing executes unless a named human
has read it and approved it, and nothing that can change the system ever
executes.**

## What is different on Linux

**Author with the Linux profile.**

```bash
python3 -m stigprep parse U_CAN_Ubuntu_24-04_LTS_V1R6_STIG.zip --format json
python3 -m stigscan author out/*ubuntu*_checklist.json -o checkpacks/ubuntu-24.04-v1r6.json --platform linux
```

(`--platform` defaults to the platform the command runs on; state it anyway.)

**Expect a lower reducible fraction than macOS, and say so.** DISA writes
macOS checks as shell snippets with an explicit acceptance sentence. Linux
checks are prose with sample output, and the sentences vary. The extractor
maps only the unambiguous shapes — "if any output is returned", "if the
package is installed / not installed", "if the command returns X", "if X is
not set to Y", "if the command does not return a line that matches the
example" — and leaves the rest UNSUPPORTED rather than guess. On the
Ubuntu 24.04 V1R6 STIG that is about a third of the rules; on RHEL 9 V2R9
about a third. Tell the user the number `author` prints, and that the
remainder need a human or an AI-assisted authoring pass, reviewed like
everything else.

**Many checks need root.** Reading `/etc/shadow`, audit rules, and most of
`/etc` requires it. `author` strips `sudo` from the command and marks the
check `requires_root`; the scan skips those unless run as root. Show the
user how many are affected before they run, and let them choose:

```bash
sudo python3 -m stigscan scan checkpacks/ubuntu-24.04-v1r6.json -o out/ --record evidence/$(date +%F)/
```

**The safety gate refuses anything that changes the system** — `systemctl
enable`, `sysctl -w`, `ufw enable`, `auditctl -w`, package installs, account
changes, firewall rules, boot configuration. A check that trips it is
reported as ERROR, never pass or fail. If `verify` lists objections on
unreviewed checks, that is the gate working; mention them, do not "fix" them
by editing the command.

**Regex-derived checks.** Where the STIG says "if the command does not return
a line that matches the example", the check's expected value is a regex
built from DISA's example output, anchored at the line start so a
commented-out line does not match. When reviewing such a check with the
user, show them the regex and the example line it came from; DISA's example
sometimes carries a distribution-specific path or version.

**Empty output is not evidence.** A check that expects "anything but X" and
gets nothing back is reported as ERROR, not pass. Explain that when it
happens: the command ran but produced nothing to judge, usually because a
service or tool is absent on that host.

## Example

Input: "scan this Ubuntu server against the STIG".

Actions: `author --platform linux` → 194 rules, 72 reducible, 122 unsupported
→ `verify` → `review --severity high --show` (13 high-confidence) → user
approves 6 by name → `sudo … scan --record` → report: "6 of 194 rules were
actually evaluated; 2 pass, 3 fail, 1 error (systemctl returned nothing);
188 not evaluated (122 not yet authored, 66 unreviewed)."

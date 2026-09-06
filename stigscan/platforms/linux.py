"""Linux profile — Ubuntu / RHEL family.

Status: allowlist and extractor written against the Canonical Ubuntu 24.04
LTS V1R6 and Red Hat Enterprise Linux 9 V2R9 STIG check text. The scanner
runs on Linux with the same review and safety gates as macOS. Treat the
first pack authored for a new distribution as a candidate set to be read,
not a validated one.
"""

from __future__ import annotations

import re

NAME = "linux"
SUPPORTED = True
EXTRACTOR = True
SHELL_CANDIDATES = ("/bin/bash", "/bin/sh", "/usr/bin/bash")

_READONLY = {
    # system / service / kernel state
    "systemctl", "sysctl", "uname", "hostnamectl", "timedatectl", "localectl",
    "journalctl", "dmesg", "lsmod", "modprobe", "lsblk", "findmnt", "mount",
    "df", "du", "free", "uptime", "ps", "pgrep", "ss", "ip", "nmcli", "ufw",
    "iptables", "ip6tables", "nft", "firewall-cmd", "auditctl", "ausearch",
    "aureport", "getenforce", "sestatus", "semanage", "getsebool", "aa-status",
    "apparmor_status", "fips-mode-setup", "update-crypto-policies",
    # packages
    "dpkg", "dpkg-query", "apt", "apt-cache", "apt-mark", "rpm", "dnf", "yum",
    "snap", "debsums",
    # accounts / auth
    "getent", "id", "whoami", "who", "w", "last", "lastlog", "faillock",
    "chage", "passwd", "pwck", "grpck", "authselect", "pam-auth-update",
    # files / text
    "cat", "ls", "stat", "find", "file", "grep", "egrep", "fgrep", "awk",
    "sed", "cut", "sort", "uniq", "head", "tail", "tr", "wc", "expr", "test",
    "echo", "printf", "date", "basename", "dirname", "xargs", "readlink",
    "realpath", "md5sum", "sha256sum", "sha512sum", "diff", "cmp", "column",
    "tee", "more", "less", "column", "nl", "paste", "tac", "rev", "strings",
    "ls", "stat", "sudo",
    # ssh / crypto / misc read-only
    "sshd", "ssh-keygen", "openssl", "gpg", "update-alternatives", "ls",
    "chkconfig", "service", "crontab", "at", "atq", "lsattr", "getfacl",
    "getcap", "setcap", "ausearch", "fapolicyd-cli", "tmux", "screen",
    "grub2-editenv", "grubby", "bootctl", "efibootmgr", "mokutil", "sgdisk",
    "blkid", "lsusb", "lspci", "dmidecode", "arch", "nproc", "env", "printenv",
}
_PREFIXES = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/")
ALLOWED_BINARIES = {p + b for p in _PREFIXES for b in _READONLY}

ALLOWED_BAREWORDS = _READONLY | {
    "if", "then", "else", "elif", "fi", "for", "do", "done", "while", "case",
    "esac", "in", "return", "break", "continue", "local", "true", "false",
    "function", "read", "command", "type", "which", "export",
}

# Mutating forms of tools that are otherwise read-only. A check may *query*
# systemctl, sysctl, ufw, auditctl, chage, passwd — never change them.
FORBIDDEN = [
    (r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask|edit|set-property|set-default|isolate|daemon-reload)\b", "changes service state"),
    (r"\bsysctl\s+(-w|--write|-p|--load|--system)\b", "writes kernel parameters"),
    (r"\bsysctl\s+[\w.]+=\S", "writes a kernel parameter"),
    (r"\bmodprobe\s+(-r|--remove)\b", "unloads a kernel module"),
    (r"\b(ufw)\s+(enable|disable|allow|deny|reject|delete|reset|default|route|limit)\b", "changes firewall state"),
    (r"\b(iptables|ip6tables)\s+-(A|I|D|F|X|P|N|R|Z)\b", "changes firewall rules"),
    (r"\bnft\s+(add|delete|flush|insert|replace|create|destroy)\b", "changes firewall rules"),
    (r"\bfirewall-cmd\s+--(add|remove|set|new|delete|permanent|reload)", "changes firewall state"),
    (r"\bauditctl\s+-[wWaAdDe]\b", "changes audit rules"),
    (r"\b(dpkg|apt|apt-get|dnf|yum|rpm|snap)\s+(-i|install|remove|purge|reinstall|upgrade|update|autoremove|-e|--erase|refresh)\b", "installs or removes software"),
    (r"\bapt-mark\s+(hold|unhold|manual|auto)\b", "changes package state"),
    (r"\bchage\s+-[mMWEdI]\b", "changes password ageing"),
    (r"\bpasswd\s+(-l|-u|-d|-e|-x|-n|-w|-i)\b", "changes an account"),
    (r"\b(useradd|usermod|userdel|groupadd|groupmod|groupdel|adduser|deluser|gpasswd)\b", "changes accounts or groups"),
    (r"\b(setenforce|semanage\s+(fcontext|port|boolean|login|user)\s+-[amd]|setsebool|restorecon|chcon)\b", "changes SELinux state"),
    (r"\b(aa-enforce|aa-complain|aa-disable)\b", "changes AppArmor state"),
    (r"\bauthselect\s+(select|apply-changes|enable-feature|disable-feature)\b", "changes authentication configuration"),
    (r"\bpam-auth-update\s+--(enable|remove|force)\b", "changes PAM configuration"),
    (r"\b(update-grub|grub2-mkconfig|grub-mkconfig|grubby\s+--(update|remove|args|set)|grub2-editenv\s+.*\s(set|unset))\b", "changes boot configuration"),
    (r"\b(fips-mode-setup\s+--(enable|disable)|update-crypto-policies\s+--set)\b", "changes crypto policy"),
    (r"\b(timedatectl|hostnamectl|localectl)\s+set-", "changes system settings"),
    (r"\bnmcli\s+\S+\s+(add|modify|delete|up|down|connect|disconnect|reload)\b", "changes network configuration"),
    (r"\bip\s+(link|addr|address|route|rule|neigh)\s+(add|del|delete|set|change|replace|flush)\b", "changes network configuration"),
    (r"\bsetcap\s+(?!-v)", "changes file capabilities"),
    (r"\b(chattr|setfacl|mkfs\S*|fdisk|parted|sgdisk\s+-[nNdDcC])\b", "mutating filesystem verb"),
    (r"\bcrontab\s+(-r|-e)\b|\bcrontab\s+[^-\s]", "modifies scheduled jobs"),
    (r"\bat\s+(?!-[lq])\S", "schedules a job"),
    (r"\bopenssl\s+(req|genrsa|genpkey|ca|x509\s+.*-signkey)\b", "creates keys or certificates"),
    (r"\bssh-keygen\b(?!\s+-[lEfF])", "creates keys"),
    (r"\bgpg\s+--(import|delete|gen-key|sign)\b", "changes keyring"),
    (r"\bupdate-alternatives\s+--(install|set|remove|auto|config)\b", "changes alternatives"),
    (r"\|\s*tee\s+(?!/dev/null)", "writes output to a file"),
    (r"\b(shutdown|reboot|halt|poweroff|init\s+[06]|telinit)\b", "reboots or halts the system"),
]

ABS_PATH = re.compile(r"(?<![\w./])(/(?:usr/bin|usr/sbin|usr/local/bin|bin|sbin)/[\w.-]+)")

GUI_HINT = re.compile(
    r"\b(interview the|ask the (?:SA|ISSO|system administrator)|verify with the (?:SA|ISSO)|"
    r"documented with the ISSO|organizational policy|review the documentation|"
    r"check with the ISSO)\b", re.I)

_PROMPT = re.compile(r"^\s*[$#]\s+")
_OUTPUT_HINT = re.compile(r"^\s*(?:example )?output\s*:?\s*$", re.I)


def clean_command(body: str) -> str:
    """Linux check text writes commands as prompt lines followed by sample
    output. Keep the prompt lines, drop the sample output, strip the prompts.

        $ sudo sysctl kernel.randomize_va_space
        kernel.randomize_va_space = 2

    -> ``sudo sysctl kernel.randomize_va_space``  (sudo is handled upstream)
    """
    lines = body.strip("\n").splitlines()
    prompted = [ln for ln in lines if _PROMPT.match(ln)]
    if prompted:
        return "\n".join(_PROMPT.sub("", ln).rstrip() for ln in prompted).strip()
    # No prompts at all: take the block up to an "Output:" marker or a blank
    # line that is followed by something that does not look like a command.
    keep: list[str] = []
    for ln in lines:
        if _OUTPUT_HINT.match(ln):
            break
        keep.append(ln.rstrip())
    return "\n".join(keep).strip()


# ---------------------------------------------------------------------------
# Acceptance sentences. DISA's Linux check text is prose with a handful of
# recurring shapes. Only shapes whose meaning is unambiguous are mapped to a
# comparator here; everything else is left for a human or AI author, as
# UNSUPPORTED, rather than guessed.
# ---------------------------------------------------------------------------
_S = {
    "empty": [
        r"If any output is returned, this is a finding",
        r"If (?:any )?(?:lines?|results?|entries|files?|accounts?|users?) (?:are|is) (?:returned|listed|found|displayed), this is a finding",
        r'If the "[^"]+" package is installed(?! and)[^.\n]*, this is a finding',
        r"If the command returns (?:any )?(?:output|results?|lines?), this is a finding",
    ],
    "nonempty": [
        r'If the "[^"]+" package is not installed, this is a finding',
        r"If the command does not return (?:a line|any output|output|a result|results?)(?:, or the line is commented out)?, this is a finding",
        r"If (?:no|nothing) (?:output|line|result)s? (?:is|are) returned, this is a finding",
        r"If the (?:service|daemon|module|rule|line) is not (?:active|enabled|loaded|present|listed|returned), this is a finding",
    ],
}
_MATCH_EXAMPLE = re.compile(r"If the command does not return (?:a line|lines|any output|output)(?: that| which)? match(?:es|ing)? the example(?:,| or)[^.\n]*, this is a finding", re.I)
_RETURNS_BAD = re.compile(r'If the command (?:above )?returns\s+"([^"]+)", this is a finding', re.I)
_NOT_RETURNED = re.compile(r'If "([^"]+)" is not returned, this is a finding', re.I)
_SAMPLE_VALUE = re.compile(r'If .{0,80}?\bis not set to\s+"([^"]+)"', re.I)
_VALUE_RETURNED = re.compile(r'If a value of\s+"([^"]+)"\s+(?:or (?:less|more) permissive )?is not returned', re.I)
_PARAM_NOT = re.compile(r'If the value (?:for|of) the "([^"]+)" (?:parameter|option|keyword|setting) is not "([^"]+)"', re.I)
_KEY_NOT_SET = re.compile(r'If "([^"]+)" is not set to "([^"]+)"', re.I)


def _sample_output(body: str) -> list[str]:
    """Lines in the check block that are not prompt lines: DISA's example of
    compliant output."""
    out = []
    for ln in body.strip("\n").splitlines():
        if _PROMPT.match(ln) or not ln.strip():
            continue
        out.append(ln.strip())
    return out


def expected(check_text: str, body: str):
    """Return (comparator, expected, verbatim_sentence, confidence, note) or None."""
    text = check_text
    for comp, patterns in _S.items():
        for pat in patterns:
            m = re.search(pat, text, re.I)
            if m:
                note = ""
                conf = "high"
                if "commented out" in m.group(0):
                    conf = "medium"
                    note = "nonempty output proves the line exists; confirm it is not commented out"
                return (comp, "", m.group(0).strip(), conf, note)
    # "is not set to X" / "value X is not returned" / "parameter is not X":
    # build an anchored regex from the key and value in the sentence.
    for pat in (_KEY_NOT_SET, _PARAM_NOT):
        m = pat.search(text)
        if m:
            key, val = m.group(1), m.group(2)
            rx = r"(?im)^\s*" + re.escape(key) + r"\s*[=:]?\s*" + re.escape(val) + r"\b"
            return ("regex", rx, m.group(0).strip(), "medium",
                    "regex derived from the sentence; confirm against the sample output")
    m = _MATCH_EXAMPLE.search(text)
    if m:
        samples = _sample_output(body)
        if samples:
            alts = "|".join(re.escape(ln).replace(r"\ ", r"\s+") for ln in samples[:6])
            rx = r"(?im)^\s*(?:" + alts + r")\s*$"
            return ("regex", rx, m.group(0).strip(), "medium",
                    "regex built from DISA's example output; a leading '#' will not match, which covers the commented-out case")
        return None
    m = _RETURNS_BAD.search(text)
    if m:
        return ("not_equals", m.group(1), m.group(0).strip(), "high", "")
    m = _NOT_RETURNED.search(text)
    if m:
        return ("contains", m.group(1), m.group(0).strip(), "medium", "expects the quoted value somewhere in the output")
    m = _VALUE_RETURNED.search(text)
    if m:
        val = m.group(1)
        return ("contains", val, m.group(0).strip(), "medium",
                "expects the value to appear in the output; 'or less permissive' is not evaluated")
    m = _SAMPLE_VALUE.search(text)
    if m:
        samples = _sample_output(body)
        val = m.group(1)
        for ln in samples:
            if val in ln:
                rx = r"(?im)^\s*" + re.escape(ln).replace(r"\ ", r"\s*").replace("=", r"\s*=\s*")
                return ("regex", rx, m.group(0).strip(), "medium",
                        "regex derived from DISA's sample output line; confirm it is not distribution-specific")
        return ("contains", val, m.group(0).strip(), "low",
                "value taken from the sentence; no sample output to anchor it")
    return None

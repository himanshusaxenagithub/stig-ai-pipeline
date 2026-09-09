"""Windows profile.

Scanning runs through PowerShell. DISA writes Windows check text not as
commands but as structured descriptions: a registry value to inspect, an
audit subcategory to confirm, a security-policy setting to read, or a
PowerShell cmdlet to run, each followed by an acceptance sentence. This
extractor maps the four regular shapes to read-only commands:

* registry ......... Get-ItemProperty on the named hive/path/value
* auditpol ......... auditpol /get /subcategory:"..." (read-only)
* security policy .. secedit /export to a temp file, then read one key
                     (DISA gives the key name for server-core installs)
* PowerShell ....... the read-only cmdlet DISA quotes

GUI-only procedures (gpedit paths with no secedit fallback, Computer
Management, interview questions) are marked MANUAL, as on other platforms.
"""

from __future__ import annotations

import re

NAME = "windows"
SUPPORTED = True
EXTRACTOR = True
SHELL_CANDIDATES = ("pwsh.exe", "powershell.exe", "pwsh", "powershell")
SHELL_ARGS = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command")

_READONLY = {
    "Get-ItemProperty", "Get-ItemPropertyValue", "Get-ChildItem", "Get-Item",
    "Get-Service", "Get-Process", "Get-WindowsFeature", "Get-WindowsOptionalFeature",
    "Get-HotFix", "Get-ComputerInfo", "Get-CimInstance", "Get-WmiObject",
    "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember", "Get-Acl",
    "Get-BitLockerVolume", "Get-Tpm", "Get-MpComputerStatus", "Get-MpPreference",
    "Get-NetFirewallProfile", "Get-NetFirewallRule", "Get-ScheduledTask",
    "Get-AppLockerPolicy", "Get-ExecutionPolicy", "Get-Content", "Get-Date",
    "Get-Volume", "Get-Disk", "Get-Partition", "Get-NetAdapter", "Get-DnsClient",
    "Get-SmbServerConfiguration", "Get-SmbClientConfiguration", "Get-WinEvent",
    "Get-EventLog", "Get-Command", "Get-Module", "Get-CimClass", "Get-NetIPAddress",
    "Select-Object", "Select-String", "Where-Object", "ForEach-Object",
    "Measure-Object", "Sort-Object", "Format-List", "Format-Table", "Out-String",
    "Out-Null", "Test-Path", "Compare-Object", "ConvertTo-Json", "Write-Output",
    "Join-Path", "Remove-Item",   # Remove-Item allowed ONLY for the secedit temp file (see FORBIDDEN)
    "reg", "auditpol", "AuditPol", "gpresult", "secedit", "Secedit", "whoami",
    "systeminfo", "winver", "sc", "sc.exe", "net", "wmic", "manage-bde", "dism",
    "netsh", "ipconfig", "certutil", "icacls", "cipher",
}
ALLOWED_BINARIES: set[str] = set()
ALLOWED_BAREWORDS = _READONLY | {
    "if", "else", "elseif", "foreach", "return", "$null", "$true", "$false",
    "try", "catch", "finally", "switch", "param", "function", "f", "v",
    # PowerShell aliases and operators that appear as bare words in DISA's quoted commands
    "Where", "where", "Select", "select", "ForEach", "foreach", "Sort", "sort",
    "Measure", "measure", "-and", "-or", "-not", "-eq", "-ne", "-like", "-match",

}

FORBIDDEN = [
    (r"\b(Set|New|Add|Enable|Disable|Install|Uninstall|Start|Stop|Restart|Clear|Invoke|Rename|Move|Copy|Import|Register|Unregister|Grant|Revoke|Update|Suspend|Resume|Reset)-\w+", "mutating cmdlet verb"),
    # Remove-Item is permitted only against the secedit scratch file this extractor creates.
    (r"\bRemove-Item\b(?!\s+\$f\s+-Force)", "Remove-Item outside the secedit temp-file cleanup"),
    (r"\breg(\.exe)?\s+(add|delete|import|restore|load|unload|copy)\b", "modifies the registry"),
    (r"\b[Aa]udit[Pp]ol\s+/(set|clear|remove|restore|backup)\b", "changes audit policy"),
    (r"\b[Ss]ecedit\s+/(configure|import|validate|generaterollback)\b", "applies security policy"),
    (r"\bsc(\.exe)?\s+(config|start|stop|delete|create|failure|pause|continue)\b", "changes service state"),
    (r"\bnet\s+(user|localgroup|accounts|share|start|stop)\s+\S+\s+(/add|/delete|/active|/expires|/times|/passwordchg|/lockoutthreshold)", "changes accounts, groups or services"),
    (r"\bnetsh\b(?!.*\bshow\b)", "netsh in a non-show form"),
    (r"\bmanage-bde\s+-(on|off|protectors|changepin|changekey|lock|unlock|forcerecovery|autounlock)\b", "changes BitLocker state"),
    (r"\bdism\b.*/(enable|disable|add|remove|cleanup)-", "changes Windows features"),
    (r"\bwmic\b.*\b(call|set|create|delete)\b", "mutating WMI operation"),
    (r"\bicacls\b.*\s/(grant|deny|remove|reset|setowner|inheritance)", "changes permissions"),
    (r"\bcipher\b\s+/[wekd]", "cipher in a mutating form"),
    (r"\b(Out-File|Set-Content|Add-Content|Export-Csv|Export-Clixml)\b", "writes output to a file"),
    (r"(?<![0-9<>])>(?!=)", "output redirection to a file"),
    (r"\b(Invoke-WebRequest|Invoke-RestMethod|curl|wget|Start-BitsTransfer|iwr|irm)\b", "network client"),
    (r"\b(Invoke-Expression|iex)\b", "dynamic evaluation"),
    (r"\b(Restart-Computer|Stop-Computer|shutdown|logoff)\b", "reboots, halts or logs off"),
    (r"\b(rm|del|erase|rmdir|rd|Format-Volume|format)\b", "destructive filesystem verb"),
]

ABS_PATH = re.compile(r"(?<![\w.\\])([A-Za-z]:\\(?:[\w .()-]+\\)*[\w.-]+\.exe)", re.I)
GUI_HINT = re.compile(
    r"\b(Computer Management|Local Users and Groups|Server Manager|Device Manager|"
    r"Control Panel|Programs and Features|Turn Windows features on or off|"
    r"Windows Security|interview the|ask the (?:SA|ISSO|system administrator)|"
    r"verify with the (?:SA|ISSO)|documented with the ISSO|review the documentation|"
    r"organizational policy|physically|BIOS|UEFI firmware)\b", re.I)

# ----------------------------------------------------------------------
# Shape 1: registry values
# ----------------------------------------------------------------------
_HIVES = {
    "HKEY_LOCAL_MACHINE": "HKLM:", "HKLM": "HKLM:",
    "HKEY_CURRENT_USER": "HKCU:", "HKCU": "HKCU:",
    "HKEY_USERS": "Registry::HKEY_USERS",
    "HKEY_CLASSES_ROOT": "Registry::HKEY_CLASSES_ROOT",
}
_REG_BLOCK = re.compile(
    r"Registry Hive:\s*(?P<hive>HKEY_[A-Z_]+|HK[A-Z]{2,3})\s*\n"
    r"\s*Registry Path:\s*(?P<path>\\?[^\n]+?)\s*\n"
    r"(?:\s*\n)*"
    r"\s*Value Name:\s*(?P<name>[^\n]+?)\s*\n"
    r"(?:\s*\n)*"
    r"(?:\s*(?:Value )?Type:\s*(?P<type>REG_[A-Z_]+)\s*\n)?"
    r"(?:\s*\n)*"
    r"\s*Value:\s*(?P<value>[^\n]+)", re.I)
_HEX_PAREN = re.compile(r"0x[0-9a-f]+\s*\((\d+)\)", re.I)
_MISSING_IS_FINDING = re.compile(r"does not exist or is not configured as specified, this is a finding", re.I)
_ONE_OR_MORE = re.compile(r"If one of the following registry values", re.I)
_OR_LESS = re.compile(r"\(or (less|greater|lower|higher)\)|or less|or greater|or fewer", re.I)


def _expected_from_reg_value(raw: str) -> tuple[str, str]:
    raw = _OR_LESS.sub("", raw).strip()
    m = _HEX_PAREN.search(raw)
    if m:
        return ("equals", m.group(1))
    if re.fullmatch(r"0x[0-9a-f]+", raw, re.I):
        return ("equals", str(int(raw, 16)))
    if re.fullmatch(r"\d+", raw):
        return ("equals", raw)
    return ("equals", raw.strip('"').strip())


def _registry_check(text: str):
    blocks = list(_REG_BLOCK.finditer(text))
    if not blocks:
        return None
    b = blocks[0]
    hive = _HIVES.get(b.group("hive").upper())
    if not hive:
        return None
    path = b.group("path").strip().rstrip("\\")
    name = b.group("name").strip().strip('"')
    raw_value = b.group("value")
    alts = [m.group(1) for m in _HEX_PAREN.finditer(raw_value)]
    if len(alts) > 1 and re.search(r"\bor\b", raw_value):
        comparator, expected = ("regex", r"^(?:" + "|".join(re.escape(a) for a in alts) + r")$")
    else:
        comparator, expected = _expected_from_reg_value(raw_value)
    if not path.startswith("\\"):
        path = "\\" + path
    ps_path = hive + path
    cmd = f"(Get-ItemProperty -Path '{ps_path}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}'"
    conf, notes = "high", []
    if len(blocks) > 1:
        conf = "medium"; notes.append(f"check text lists {len(blocks)} registry values; only the first is checked here; add the others as separate checks or review manually")
    if _ONE_OR_MORE.search(text):
        conf = "medium"; notes.append("STIG accepts one of several values; confirm the comparison")
    if _OR_LESS.search(b.group("value")):
        comparator = "int_le" if re.search(r"less|lower|fewer", b.group("value"), re.I) else "int_ge"
        conf = "medium"; notes.append("range comparison derived from '(or less/greater)'")
    src = _MISSING_IS_FINDING.search(text)
    return (cmd, comparator, expected, src.group(0) if src else "registry value as specified", conf, "; ".join(notes))


# ----------------------------------------------------------------------
# Shape 2: audit policy
# ----------------------------------------------------------------------
_AUDIT_LINE = re.compile(r"^\s*([A-Za-z /]+?)\s*>>\s*([A-Za-z /-]+?)\s*-\s*(Success and Failure|Success|Failure)\s*$", re.M)


def _auditpol_check(text: str):
    if not re.search(r"AuditPol", text, re.I):
        return None
    m = _AUDIT_LINE.search(text)
    if not m:
        return None
    subcat, want = m.group(2).strip(), m.group(3).strip()
    cmd = f'auditpol /get /subcategory:"{subcat}" /r | Select-String -Pattern "{subcat}"'
    alt = "Success and Failure" if want == "Success and Failure" else f"(?:{re.escape(want)}|Success and Failure)"
    rx = "(?i)" + re.escape(subcat) + r".*?," + alt
    src = re.search(r"If the system does not audit the following, this is a finding", text, re.I)
    return (cmd, "regex", rx, src.group(0) if src else "audit subcategory as specified", "medium",
            "auditpol /r CSV output; 'Success and Failure' satisfies a Success-only or Failure-only requirement")


# ----------------------------------------------------------------------
# Shape 3: security policy with a secedit fallback
# ----------------------------------------------------------------------
_SECEDIT_KEY_EQ = re.compile(r'If "([A-Za-z0-9_]+)" equals "([^"]+)" in the file, this is a finding', re.I)
_SECEDIT_KEY_NE = re.compile(r'If "([A-Za-z0-9_]+)" (?:is not|does not equal|is not set to) "([^"]+)" in the file, this is a finding', re.I)
_SECEDIT_KEY_GT = re.compile(r'If "([A-Za-z0-9_]+)" is greater than "(\d+)"', re.I)
_SECEDIT_KEY_LT = re.compile(r'If "([A-Za-z0-9_]+)" is less than "(\d+)"', re.I)
_SECEDIT_READ = ("$f = Join-Path $env:TEMP ('secpol_' + [guid]::NewGuid() + '.inf'); "
                 "secedit /export /areas SecurityPolicy /cfg $f | Out-Null; "
                 "$v = Select-String -Path $f -Pattern '^{key}\\s*=' | ForEach-Object {{ ($_.Line -split '=',2)[1].Trim() }}; "
                 "Remove-Item $f -Force; $v")


def _secedit_check(text: str):
    if not re.search(r"\bSecedit\b", text, re.I):
        return None
    m = _SECEDIT_KEY_EQ.search(text)
    if m:
        return (_SECEDIT_READ.format(key=m.group(1)), "not_equals", m.group(2), m.group(0), "high", "")
    m = re.search(r'If "([A-Za-z0-9_]+)" is not something other than "([^"]+)" in the file, this is a finding', text, re.I)
    if m:
        return (_SECEDIT_READ.format(key=m.group(1)), "not_equals", m.group(2), m.group(0), "high", "")
    m = _SECEDIT_KEY_NE.search(text)
    if m:
        return (_SECEDIT_READ.format(key=m.group(1)), "equals", m.group(2), m.group(0), "high", "")
    m = _SECEDIT_KEY_GT.search(text)
    if m:
        return (_SECEDIT_READ.format(key=m.group(1)), "int_le", m.group(2), m.group(0), "medium",
                "'greater than X' mapped to <= X; any second condition (e.g. 'or equal to 0') is not evaluated")
    m = _SECEDIT_KEY_LT.search(text)
    if m:
        return (_SECEDIT_READ.format(key=m.group(1)), "int_ge", m.group(2), m.group(0), "medium", "'less than X' mapped to >= X")
    return None


# ----------------------------------------------------------------------
# Shape 4: a quoted read-only PowerShell command with an acceptance sentence
# ----------------------------------------------------------------------
_PS_CMD = re.compile(r'(?:Enter|Run|Execute|Type)\s+"((?:Get-|Test-|whoami|systeminfo|manage-bde|reg query|auditpol|gpresult)[^"\n]{3,300})"', re.I)
_PS_RETURNS_BAD = re.compile(r'If (?:the (?:command|value|result|output)|this|"[^"]+") (?:returns|is|displays)\s+"([^"]+)", this is a finding', re.I)
_PS_NOT_RETURNS = re.compile(r'If (?:the (?:command|value|result|output)|this) (?:is not|does not return|does not display)\s+"([^"]+)", this is a finding', re.I)
_PS_ANY_OUTPUT = re.compile(r"If (?:any|there are any|the command returns any) (?:results?|output|items?|entries|values?) (?:are |is )?(?:returned|listed|displayed|found)?, this is a finding", re.I)
_PS_NO_OUTPUT = re.compile(r"If (?:no|nothing) (?:results?|output|items?|entries|values?) (?:are |is )?(?:returned|listed|displayed|found), this is a finding", re.I)


def _powershell_check(text: str):
    m = _PS_CMD.search(text)
    if not m:
        return None
    cmd = m.group(1).strip()
    for pat, comp, conf, note in ((_PS_NOT_RETURNS, "contains", "medium", "expects the quoted value in the output"),
                                  (_PS_RETURNS_BAD, "not_equals", "medium", ""),
                                  (_PS_ANY_OUTPUT, "empty", "high", ""),
                                  (_PS_NO_OUTPUT, "nonempty", "high", "")):
        e = pat.search(text)
        if e:
            expected = e.group(1) if e.groups() else ""
            return (cmd, comp, expected, e.group(0), conf, note)
    return None


def extract(check_text: str):
    """Return (command, comparator, expected, source_sentence, confidence, note) or None."""
    for fn in (_registry_check, _auditpol_check, _secedit_check, _powershell_check):
        got = fn(check_text)
        if got:
            return got
    return None


def clean_command(body: str) -> str:
    return body.strip("\n").strip()

"""Windows profile — NOT YET SUPPORTED for scanning.

What exists: the safety vocabulary — read-only PowerShell cmdlets and
commands a check may use, and the mutating forms it may not — so that the
review and verify steps work on a Windows pack once one can be authored.

What does not exist: an extractor. DISA writes Windows check text as
registry paths, Group Policy paths and GUI steps rather than as commands, so
reducing it to executable checks needs a different authoring approach from
the shell-snippet extractor used for macOS and Linux. Until that is built,
``stigscan author --platform windows`` marks every rule UNSUPPORTED with an
explanatory note, and ``stigscan scan`` refuses a Windows pack.
"""

from __future__ import annotations

import re

NAME = "windows"
SUPPORTED = False
EXTRACTOR = False
SHELL_CANDIDATES = ("powershell.exe", "pwsh.exe")
SHELL_ARGS = ("-NoProfile", "-NonInteractive", "-Command")

_READONLY = {
    "Get-ItemProperty", "Get-ItemPropertyValue", "Get-ChildItem", "Get-Item",
    "Get-Service", "Get-Process", "Get-WindowsFeature", "Get-WindowsOptionalFeature",
    "Get-HotFix", "Get-ComputerInfo", "Get-CimInstance", "Get-WmiObject",
    "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember", "Get-Acl",
    "Get-BitLockerVolume", "Get-Tpm", "Get-MpComputerStatus", "Get-MpPreference",
    "Get-NetFirewallProfile", "Get-NetFirewallRule", "Get-ScheduledTask",
    "Get-AppLockerPolicy", "Get-ExecutionPolicy", "Get-Content", "Select-Object",
    "Select-String", "Where-Object", "ForEach-Object", "Measure-Object",
    "Sort-Object", "Format-List", "Format-Table", "Out-String", "Test-Path",
    "Compare-Object", "ConvertTo-Json", "Write-Output",
    "reg", "auditpol", "gpresult", "secedit", "whoami", "systeminfo", "winver",
    "sc", "net", "wmic", "manage-bde", "dism", "netsh",
}
ALLOWED_BINARIES: set[str] = set()
ALLOWED_BAREWORDS = _READONLY | {"if", "else", "elseif", "foreach", "return", "$null", "$true", "$false"}

FORBIDDEN = [
    (r"\b(Set|New|Remove|Add|Enable|Disable|Install|Uninstall|Start|Stop|Restart|Clear|Invoke|Rename|Move|Copy|Import|Export|Register|Unregister|Grant|Revoke|Update)-\w+", "mutating cmdlet verb"),
    (r"\breg\s+(add|delete|import|restore|load|unload|copy)\b", "modifies the registry"),
    (r"\bauditpol\s+/(set|clear|remove|restore)\b", "changes audit policy"),
    (r"\bsecedit\s+/(configure|import)\b", "applies security policy"),
    (r"\bsc\s+(config|start|stop|delete|create|failure)\b", "changes service state"),
    (r"\bnet\s+(user|localgroup|accounts|share|start|stop)\s+\S+\s+\S", "changes accounts, groups or services"),
    (r"\bnetsh\b(?!.*\bshow\b)", "netsh in a non-show form"),
    (r"\bmanage-bde\s+-(on|off|protectors|changepin|changekey|lock|unlock|forcerecovery)\b", "changes BitLocker state"),
    (r"\bdism\b.*/(enable|disable|add|remove)-", "changes Windows features"),
    (r"\bwmic\b.*\b(call|set|create|delete)\b", "mutating WMI operation"),
    (r"\b(Out-File|Set-Content|Add-Content)\b|(?<![0-9<>])>(?!=)", "writes output to a file"),
    (r"\b(Invoke-WebRequest|Invoke-RestMethod|curl|wget|Start-BitsTransfer)\b", "network client"),
    (r"\b(Restart-Computer|Stop-Computer|shutdown)\b", "reboots or halts the system"),
]

ABS_PATH = re.compile(r"(?<![\w.\\])([A-Za-z]:\\(?:[\w .-]+\\)*[\w.-]+\.exe)", re.I)
GUI_HINT = re.compile(r"\b(Run \"|Navigate to|Open \"|Select \"|click|Local Group Policy Editor|Computer Configuration >>)", re.I)


def clean_command(body: str) -> str:
    return body.strip("\n").strip()

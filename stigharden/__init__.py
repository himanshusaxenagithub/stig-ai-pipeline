"""stig-harden — draft remediation scripts from scan findings.

Module 4 of stig-ai-pipeline. Consumes a stig-scan JSON report (and
optional checklist / check pack) and writes platform-appropriate
remediation *drafts*. A named person reviews the script; approval
freezes a digest. Nothing is applied unless that person later runs
``apply --apply-for-real``, which is refused in CI.

Design rule: AI may help *author* a fix. It never applies an unreviewed
remediation and never runs a script because a scan failed. Default
commands are draft / show / dry-run.
"""

__version__ = "0.1.0"

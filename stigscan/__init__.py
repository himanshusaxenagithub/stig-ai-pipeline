"""stig-scan — run frozen, human-reviewed STIG checks against a live system.

Module 2 of stig-ai-pipeline. Consumes the JSON checklist produced by
stig-prep (module 1) and produces machine-readable pass/fail evidence for
stig-assess (module 3).

Design rule: AI is allowed in the *authoring* loop and never in the
*execution* loop. Candidate checks are derived offline, a human approves
them, and approval is frozen with a content digest. The scanner refuses to
execute anything that is not approved, and refuses to honour an approval
whose content has since changed.
"""

__version__ = "0.2.0"

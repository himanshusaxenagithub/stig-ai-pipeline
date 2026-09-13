"""stig-assess — draft POA&M-style entries from a stig-scan report.

Module 3 of stig-ai-pipeline. Consumes the JSON scan report produced by
stig-scan (module 2) and writes Plan of Action and Milestones drafts a
person can accept, reject, or close.

Design rule: AI may help *interpret* a finding. It never marks a finding
complete, never accepts residual risk, and never silently changes the
status a human already recorded. Drafts stay drafts until a named person
approves them. Closing is a separate, explicit human command.
"""

__version__ = "0.1.0"

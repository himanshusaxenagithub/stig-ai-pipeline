# Synthetic fixture set: unmanaged macOS 26 host

Hand-authored command output modelling a plausible unmanaged MacBook — SIP on,
FileVault enabled but not MDM-enforced, software updates current, no configuration
profiles installed. Every file carries `"_synthetic": true`.

These fixtures exist so the evaluator and report writer can be regression-tested on
any platform, including CI runners that cannot execute macOS commands. **They are not
a recording of a real system and must never be presented as scan evidence.** Capture
real fixtures with `stigscan scan <pack> --record <dir>` on the host under test.

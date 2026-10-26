# AutoTrack v2026.10.26.6 — the regression gate ships

This release exists to prove its own pipeline: it was built by `tools/release.ps1`, which **refuses to publish unless the app actually boots** — a static audit (resource keys, parse-time UI events) followed by a live smoke launch of an unelevated variant that constructs the window, switches every tab, and resolves every resource key. The two launch regressions of v2026.10.26.2/.4 would both have died at this gate.

What's new for users:

- **`--selftest`** on the command line runs the same UI self-test in the shipping app (PASS/FAIL written next to the exe) — the shell now honors the same contract as the engines.
- **Startup hardening** — engine configuration now happens before window construction, removing a load-order fragility in the Phone Home tab's first scan.
- The known-bad releases (.2, .4) are banner-marked in the Releases list.

— © 2026 Dan Park, magicpoint.ai · Apache 2.0

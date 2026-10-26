# AutoTrack — watch the services you've blocked

A lightweight, native Windows app (WinUI 3 / .NET 10) that answers one question:
**what are the services on my blocked list connecting to right now — and which
of their connects are my blocks actually dropping?**

Built on the lean slice of the [AutoScope](https://github.com/dparksports/autoscope)
F# engine libraries — TCP table, svchost identity, Sysmon connect events, and
the firewall inventory — copied here and nothing else: no probe, no decryptor,
no archive writer, no blocking. AutoTrack blocks too — **AT-BLOCK** rules, reversible everywhere:

- Right-click any row → **Block this address** (provenance `service/ip` baked into the rule).
- **Block every destination of this service…** — bulk, with a review dialog; Microsoft/CDN infra flagged red.
- **🚑 Restore Internet (all apps)** — mutual adoption: one panic button disables AutoCommand's `AC-BLOCK`, AutoScope's `AS-BLOCK` and AutoTrack's `AT-BLOCK` alike, from any of the three apps.

## What you see

- Every **connect attempt** by the tracked services, live from Sysmon EID 3 —
  including the ones your firewall blocks silently drop (they never reach the
  TCP table, but Sysmon sees them; `Blocked by` names the owning app's rule).
- Every **established connection** from the kernel's dual-family TCP table,
  attributed: svchost PIDs decoded to the hosted service via SCM ground truth,
  `msedgewebview2` tracked by image.
- Tracked services: `cryptsvc`, `diagtrack`, `netprofm`, `wuauserv`, `wlidsvc`,
  `dosvc`, `wpnservice`, `msedgewebview2` — **plus whatever else your blocked
  list names** (block provenance like "cryptsvc/Akamai" adds that service
  automatically). Chips toggle each service; "Blocked attempts only" narrows
  to the drops.

## 🔍 Trace any process instance

Pick any running process (searchable picker; svchost instances shown decoded to their hosted service) or right-click a tracker row → **Trace this process**. The trace assembles: identity card (verified spawn chain via the provenance engine, task attribution, svchost decode), every Sysmon connect *attempt* including firewall-dropped ones over the retained window, live established connections, and a destinations rollup with cadence regularity ("⏱ metronomic" when inter-arrival CV < 0.35). Right-click any destination to block it (AT-BLOCK). Session-scoped; multiple concurrent traces as chips. Byte counts deliberately omitted — Sysmon carries no payload sizes and honest volume needs the raw-capture stack this lean app omits.

## Plays with both apps

AutoTrack adopts **both** AutoCommand's `AC-BLOCK` and AutoScope's `AS-BLOCK`
rules for reporting. It creates no rules, writes no stores, changes nothing.

## Install

Download `AutoTrack-v…-win-x64.zip`, unzip, right-click `AutoTrack.exe` →
**Run as administrator** (Sysmon + full process attribution need elevation).
Deleting the folder uninstalls it.

## Build

```powershell
dotnet build AutoTrack.slnx -c Release
dotnet publish App/AutoTrack.csproj -c Release -r win-x64 --self-contained -o publish_out
```

Engine subset: `Engines.Core` (AppIdentity, IP classification) ·
`Engines.Watch` (TCP table, svchost identity, Sysmon connect watcher) ·
`Engines.Firewall` (block inventory) — F#, app-agnostic, identical files to
the AutoScope engine libraries.

Apache License 2.0 — engines © 2026 Dan Park, magicpoint.ai.

# AntiSplit Web Parity Audit

Date: 2026-06-13

This audit maps the original client-side parity goals to the current implementation evidence.

## Status Summary

| Area | Current status | Evidence |
| --- | --- | --- |
| Client-side web app | Implemented as a static Vite/React app with merge work in a Web Worker. | `npm run build` |
| Corpus confidence | Tooling implemented; current local split-container corpus is 2/2 passing in `v1` and `v1-v2` modes, with one extra standalone APK passing separately. | `npm run verify:corpus -- --report docs/corpus-results.md`, `npm run verify:corpus -- --manifest docs/local-corpus-manifest.txt --report docs/corpus-manifest-results.md`, `docs/corpus-results.md`, `docs/corpus-manifest-results.md`, `docs/corpus-standalone-results.md` |
| Corpus inventory | Implemented; local Downloads scan distinguishes usable APK archives from generic ZIP files and unpacked config-split components. | `npm run discover:corpus -- /Users/ahmadjalil/Downloads --report docs/corpus-inventory.md`, `docs/corpus-inventory.md`, `docs/corpus-inventory.json` |
| Java/REAndroid comparison | Implemented for default and arbitrary samples; REON and LibreLinkUp Markdown/JSON reports generated. | `npm run compare:java-web`, `npm run compare:java-web -- /Users/ahmadjalil/Downloads/librelinkup/LibreLinkUp_5.0.1_APKPure.xapk` |
| `resources.arsc` merge | Implemented for current single-package corpus shapes, including split string remaps, type-spec merging, standard/compact/sparse type chunks, and complex map entries. | `npm run verify:fixture`, `npm run verify:corpus -- --report docs/corpus-results.md` |
| ARSC shape scan | Implemented; current local corpus has no styled string pools, multi-package tables, or split type IDs absent from the base type string pool. | `npm run scan:arsc -- --manifest docs/local-corpus-manifest.txt --report docs/arsc-shape-report.md`, `docs/arsc-shape-report.md` |
| ARSC unsupported guards | Implemented fail-closed checks for styled string pools, multi-package tables, and missing base type IDs. | `npm run verify:arsc-guards` |
| APK Signature Scheme v2 | Implemented as `JAR/v1 + experimental v2`, with browser verification, tamper-negative tests, stale v3/v3.1/source-stamp pair rejection, bundled Java apksig verification for Android 7.0+, and Android SDK `apksigner` checks. | `npm run verify:v2-fixture`, `npm run verify:corpus -- --report docs/corpus-results.md` |
| JAR/v1 fallback | Preserved and verified for Android 4.4-6.0 using bundled Java apksig. | `npm run verify:fixture`, `npm run verify:corpus -- --report docs/corpus-results.md` |
| Environment tooling | Bounded local check implemented; Java/Javac, `sdkmanager`, the Homebrew Android SDK root, and build-tools 36.0.0 `apksigner` are present locally. | `npm run verify:environment`, `docs/environment-check.json` |
| Manifest split cleanup | Removes known split attributes, Play split metadata, and `uses-split`; preserves raw split XML resource payloads so `resources.arsc` file references remain satisfiable. | `npm run verify:fixture`, Java/web comparison reports |
| Browser-only platform limits | Documented in README, parity plan, and the web UI. | `README.md`, `docs/parity-plan.md`, `src/main.tsx` |
| Completion audit | Implemented as a machine-readable requirement status report. Current status is not complete: 7 proven, 2 partial, 1 missing. | `npm run audit:parity`, `docs/parity-completion-audit.json` |

## Verified Corpus

Current default corpus samples:

- `/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk`
- `/Users/ahmadjalil/Downloads/librelinkup/LibreLinkUp_5.0.1_APKPure.xapk`

The same independent split-container samples are listed in `docs/local-corpus-manifest.txt` so the local baseline can be expanded by appending one path per line. `docs/corpus-manifest-results.md` records the current manifest run.

Current result:

- `2/2` samples pass.
- The corpus reports record each input's byte size and SHA-256 so fixture identity is reproducible.
- Both samples pass `JAR/v1` and `JAR/v1 + v2`.
- Both samples verify with bundled Java apksig: `ok v1` for legacy Android range and `ok v2` for Android 7.0+; v2 outputs also verify with Android SDK `apksigner`.
- Unsupported and failures columns are empty.

Additional local inventory/result evidence:

- `docs/corpus-inventory.md` reports `3/27` usable archive samples under `/Users/ahmadjalil/Downloads`.
- The third usable archive is `/Users/ahmadjalil/Downloads/librelinkup/unpacked/org.nativescript.LibreLinkUp.apk`, a standalone base APK from the LibreLinkUp unpacked folder rather than an independent split package.
- `docs/corpus-standalone-results.md` records that standalone APK passing both `JAR/v1` and `JAR/v1 + v2` modes with package `org.nativescript.LibreLinkUp`.
- `docs/arsc-shape-report.md` records current ARSC shape coverage for the manifest corpus. Both independent XAPK samples pass the shape scan with no styled string pools, multi-package resource tables, or split type IDs absent from the base type string pool.

## Remaining Gaps

| Gap | Current handling | Next evidence needed |
| --- | --- | --- |
| Android SDK `apksigner` validation | Available locally from Homebrew Android command-line tools build-tools 36.0.0; `verify:v2-fixture` now runs `apksigner verify --verbose`. | Keep this in parity runs so future signing changes are checked against Android build-tools, not only browser and bundled Java apksig verifiers. |
| APK Signature Scheme v3/v4 | Minimal v3.0 is implemented as `JAR/v1 + experimental v2/v3`; v4 is implemented as a separate `.idsig` sidecar in `JAR/v1 + experimental v2/v3 + v4 sidecar`. Both have browser verification, tamper-negative fixture checks, and bundled Java apksig verification; v3 APK outputs also verify with Android SDK `apksigner`. | Browsers still cannot invoke Android incremental install APIs directly; add v3.1/proof-of-rotation only if key rotation semantics become required. |
| Styled string pool span preservation | Not implemented; guarded as unsupported. | Add real corpus sample requiring styled string preservation, then implement style span remapping and verify output. |
| Multi-package resource tables | Not implemented; guarded as unsupported. | Add real corpus sample with multi-package ARSC, then implement package-aware merge or classify as out of browser scope. |
| Type IDs absent from base type string pool | Not implemented; guarded as unsupported. | Add real corpus sample requiring base type-string-pool expansion, then implement type string pool rewrite. |
| Broad corpus confidence | Tooling exists, but only two independent local real-world XAPK split containers are available. The Downloads inventory found one additional standalone APK from the same LibreLinkUp package. | Run at least 20 independent mixed `.xapk`, `.apks`, `.apkm`, `.zip`, and standalone `.apk` samples. |
| Installed-app extraction | Browser cannot enumerate installed Android apps or read their private split APK files. | Optional Android companion/exporter, PWA share target, or user-selected exported files. |
| Android install intent | Browser cannot reliably launch Android package installer for generated APKs. | Optional Android companion installer or documented download/install flow. |

## Required Verification Set

Run this set before claiming a parity change is stable:

```sh
npm run verify:parity
```

This writes `docs/parity-run.json` with the latest step-by-step status and expands to:

```sh
npm run build
npm run verify:fixture
npm run verify:v2-fixture
npm run verify:arsc-guards
npm run verify:corpus -- --report docs/corpus-results.md
npm run verify:corpus -- --manifest docs/local-corpus-manifest.txt --report docs/corpus-manifest-results.md
npm run scan:arsc -- --manifest docs/local-corpus-manifest.txt --report docs/arsc-shape-report.md
npm run verify:environment
npm run compare:java-web
npm run compare:java-web -- /Users/ahmadjalil/Downloads/librelinkup/LibreLinkUp_5.0.1_APKPure.xapk
npm run audit:parity
```

The final completion-audit step should be treated as the authoritative local checklist for whether this browser implementation is done or still has explicit gaps.

## Completion Position

The browser implementation is substantially functional for the current local evidence set, including v2 signing, minimal v3.0 signing, v4 sidecar generation, Android SDK `apksigner` validation, and two real XAPK corpus samples. It is not yet equivalent to REAndroid/APKEditor across arbitrary APKs because broad corpus coverage and exotic ARSC layouts remain incomplete or unverified. The current machine-readable completion audit reports `complete: false`.

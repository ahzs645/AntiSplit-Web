# AntiSplit Web Parity Plan

This plan tracks the remaining differences between the browser implementation and the Android/REAndroid-backed app.

For the current requirement-by-requirement evidence audit, see `docs/parity-audit.md`.

## Current Verified Baseline

- The web app runs as a static Vite/React app and performs merging in a Web Worker.
- `/Users/ahmadjalil/Downloads/iHunter+BC_5.0.69_APKPure.xapk` passes `npm run verify:fixture`.
- The iHunter fixture merges one base plus 19 ABI, language, and density splits with no unsupported scope.
- The generated APK is JAR/v1 signed with the embedded debug key.

## Workstreams

### 1. Corpus Confidence

Goal: turn broad APK compatibility into measured evidence.

Deliverables:
- `npm run verify:corpus -- /path/to/samples --report docs/corpus-results.md`
- `npm run verify:corpus -- --manifest docs/local-corpus-manifest.txt --report docs/corpus-manifest-results.md`
- `npm run discover:corpus -- /path/to/downloads --report docs/corpus-inventory.md`
- `npm run audit:parity`
- `npm run verify:environment`
- `npm run scan:arsc -- --manifest docs/local-corpus-manifest.txt --report docs/arsc-shape-report.md`
- `npm run compare:java-web` for a repeatable REAndroid-vs-web baseline on the local iHunter fixture.
- A growing sample set covering `.xapk`, `.apks`, `.apkm`, plain `.zip`, standalone `.apk`, ABI splits, density splits, language splits, and feature splits.
- Failure classification for resource-table, manifest, signing, ZIP/alignment, and browser-platform limitations.

Exit criteria:
- At least 20 mixed real-world split packages checked.
- Every failure has a stable unsupported reason or an implementation issue.
- Fixture and corpus checks are documented in `docs/corpus-results.md`.

Historical REAndroid comparison:
- `npm run compare:java-web` writes `docs/java-web-comparison.md` and `docs/java-web-comparison-REON_POCKET_2.2.0_APKPure.md`.
- `npm run compare:java-web -- /Users/ahmadjalil/Downloads/librelinkup/LibreLinkUp_5.0.1_APKPure.xapk` writes `docs/java-web-comparison-LibreLinkUp_5.0.1_APKPure.md`.
- In both current comparisons, the raw local Java/REAndroid merge output carries the original APK Signing Block, but its v2 digest does not verify after merging.
- In both current comparisons, the web unsigned output strips stale signing material, and the web v1+v2 output writes a fresh browser-generated v2 block that verifies with `src/apkV2Verifier.ts`.

Current corpus scope:
- `npm run verify:corpus -- --report docs/corpus-results.md` checks both `v1` and `v1-v2` signing modes against the known local fixture corpus files that exist on this machine.
- `docs/local-corpus-manifest.txt` lists the independent local split-container samples one per line. It currently contains the available iHunter fixture.
- Directory inputs are scanned recursively for `.xapk`, `.apks`, `.apkm`, `.zip`, and `.apk` files.
- `npm run discover:corpus -- /Users/ahmadjalil/Downloads --report docs/corpus-inventory.md` can be regenerated to inventory the currently available iHunter fixture and any future samples.
- `npm run discover:corpus -- /Users/ahmadjalil/Downloads /Users/ahmadjalil/Desktop /Users/ahmadjalil/Documents /Users/ahmadjalil/github/AntiSplit-Web --report docs/targeted-corpus-inventory.md` reports 3 usable independent samples out of 51 ZIP/APK-like files after classifying generated `dist-fixtures/` APKs as debug outputs rather than corpus samples.
- The corpus report records bundled Java apksig status for each signing mode (`ok v1`, `ok v2`, `ok v3`, and `ok v4` where applicable) and Android SDK `apksigner` status for v2/v3 APK outputs when build-tools are available.
- The corpus report classifies warnings and failures into stable buckets: `resource-table`, `manifest`, `signing`, `zip-alignment`, `browser-platform`, or `general`.
- The current local corpus sample passes both `v1` and `v1-v2`: `/Users/ahmadjalil/Downloads/iHunter+BC_5.0.69_APKPure.xapk`.
- The unpacked LibreLinkUp base APK also passes as a standalone APK in `docs/corpus-standalone-results.md`; it is useful for the single-APK path but does not expand independent split-package coverage.

### 2. Resource Table Coverage

Current coverage:
- Single-package resource tables.
- Styled string pools are preserved and their span-name indices are remapped when pools are combined; styled strings are normalized to the contiguous prefix required by Android's resource parser.
- Type-spec flag merging.
- Standard, compact-offset, and sparse type chunks.
- Complex map entries whose entry header size includes the parent/count fields.
- Key string-pool remapping.
- Table-level `TYPE_STRING` value remapping.
- Guard regression coverage with `npm run verify:arsc-guards`, which mutates the iHunter fixture into malformed-string-pool, multi-package, and missing-base-type-ID shapes and verifies that each fails closed with a specific diagnostic.

Remaining targets:
- Multi-package resource tables.
- Type IDs absent from the base type string pool.
- Additional chunk layouts discovered by corpus runs.

Policy:
- Merge only when structural guards pass.
- Fail closed with specific diagnostics when a table shape is unsupported.
- Failed ARSC merge attempts surface concrete unsupported reasons in `result.unsupported`, including malformed string pools, multi-package tables, package identity mismatches, missing type IDs, and malformed chunks. This is intended to make corpus failures directly actionable.

### 3. APK Signature Scheme v2

Goal: add browser-side v2 signing while preserving JAR/v1 fallback.

Planned shape:
- Keep `signApk: true` producing the current v1 signature until v2 is verified.
- Add an internal `v1+v2` signer path behind a code-level option or fixture script. (Implemented experimentally in `src/apkV2Signer.ts` and `npm run verify:v2-fixture`.)
- Add a browser-side APK Signing Block detector to `apkVerification`. (Implemented: detects the block and identifies v2/v3/v3.1/source-stamp pairs.)
- Verify generated APKs with Android `apksigner verify --verbose` when the Android build tools are available.

Current v2 status:
- `npm run verify:v2-fixture` writes `dist-fixtures/iHunter+BC_5.0.69_APKPure_antisplit_v2.apk`.
- The browser verifier detects an APK Signature Scheme v2 pair (`0x7109871a`) in the APK Signing Block.
- `npm run verify:v2-fixture` asserts the generated web APK Signing Block contains exactly one fresh v2 pair and no stale v3/v3.1/source-stamp pairs carried from the source APK.
- `src/apkV2Verifier.ts` recomputes the v2 chunked SHA-256 content digest and verifies the RSA/SHA-256 signature over v2 signed-data for the generated fixture.
- `tools/verify-v2-fixture.ts` also proves the verifier fails closed when signed APK content or the v2 signing block is tampered.
- `tools/verify-v2-fixture.ts` compiles and runs the bundled Java `com.android.apksig.ApkVerifier` for Android 7.0+ and verifies that the generated APK is accepted using v2.
- ZIP central directory parsing and `unzip -t` still pass after signing-block insertion.
- `tools/verify-v2-fixture.ts` also runs Android `apksigner verify --verbose` automatically when `apksigner` is available on PATH or under `ANDROID_HOME`/`ANDROID_SDK_ROOT`.
- Android SDK `apksigner` is available locally from Homebrew Android command-line tools build-tools 36.0.0 and verifies the generated v2 fixture.
- `npm run verify:environment` records the bounded local check in `docs/environment-check.json`; the current report finds Java/Javac, `sdkmanager`, the Homebrew Android SDK root, and a working `apksigner`.
- Current JAR/v1 fallback status: the web output includes `META-INF/MANIFEST.MF`, `META-INF/ANTISPLT.SF`, and `META-INF/ANTISPLT.RSA`; desktop `jarsigner` sees the debug certificate; and bundled Java apksig verifies the v1 signature for Android 4.4-6.0. Modern target SDK 35 APKs still require v2 or newer on Android 7.0+, so v1-only output is mainly an external-signing or legacy-platform fallback.

V3/v4 note:
- v3 is useful for proof-of-rotation and SDK-targeted signer metadata, but v2 should land first.
- v4 is mainly for incremental install workflows and is lower priority for downloadable browser output.

### 4. Binary Manifest Coverage

Current coverage:
- Removes known split attributes: `requiredSplitTypes`, `splitTypes`, `isSplitRequired`.
- Removes Play split metadata: `com.android.vending.splits.required`, `com.android.vending.splits`.
- Removes `uses-split` elements.
- Removes Play split metadata XML payloads such as `res/xml/splits0.xml`.

Remaining targets:
- Corpus-driven cleanup for additional split markers.
- General binary manifest merge is not planned unless real samples require it.

### 5. Browser-Impossible Android Platform Features

Installed-app extraction:
- A normal browser cannot enumerate installed Android apps or read their private split APK files.
- Feasible alternatives: user-selected exported files, Android share target/PWA file handling, or an optional Android companion exporter.

Install flow:
- A normal browser cannot reliably launch Android's package installer for a generated APK across browsers.
- Feasible alternatives: download the APK, document the install step, or use an optional Android companion installer.

These should be documented as platform limits, not implementation bugs.

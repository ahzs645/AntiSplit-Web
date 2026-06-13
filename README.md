# AntiSplit M

Android app to merge/"AntiSplit" split APKs (APKS/XAPK/APKM) to a regular .APK file

This project is a simple GUI implementation of Merge utilities from [REAndroid APKEditor](https://github.com/REAndroid/APKEditor).

Some other apps that can perform this task like Apktool M, AntiSplit G2, NP Manager are all closed source. In addition, some older apps have a large problem in not removing the information about splits in the APK from the AndroidManifest.xml. If a merged/non-split APK contains this information it will cause an "App not installed" error on some devices. Fortunately the implementation by REAndroid fixes this issue.

Version 2.x - Material You design, support Android 4.4+

Version 1.x - Support Android 1.6+

## Usage

Video - https://youtu.be/Vk566iMG6Gs

There are 3 ways to open a split APK to be merged:

- Share the file and select AntiSplit M in the share menu
- Press (open) the file and select AntiSplit M in available options
- Open the app from launcher and press the first button then select the split APK file.

There is also a menu in the app that allows selecting an app from those installed on the device as a split APK. Please try this method if you have problems with selecting a downloaded split APK.

Note: An APK must be signed in order to install it (unless you use tool like [Core Patch](https://github.com/LSPosed/CorePatch)). If you are planning to further modify the APK, you only need to sign it after the modifications (Apps like ReVanced Manager will sign it for you). Some apps verify the signature of the APK or take other measures to check if the app was modified, which may cause it to crash on startup.

## Screenshots

| Main screen                                 | Settings                               | Selecting from installed apps                                 |
| ------------------------------------------- | -------------------------------------- | ------------------------------------------------------------- |
| ![Main screen](screenshot/2.2.7_home.jpeg) | ![Settings](screenshot/2.2.7_settings.jpeg) | ![Selecting from installed apps](screenshot/2.2.7_applist.jpeg) |

| Dialog allowing splits selection   | Processing                                 | Result                             |
| ---------------------------------- | ------------------------------------------ | ---------------------------------- |
| ![Dialog](screenshot/2.2.7_splits_list.jpeg) | ![Processing](screenshot/2.2.7_processing.jpeg) | ![Result](screenshot/2.2.7_success.jpeg) |

## Used projects

⭐ [APKEditor](https://github.com/REAndroid/APKEditor) by REAndroid, what makes it all possible

- [Android port](https://github.com/MuntashirAkon/apksig-android) of apksig library by MuntashirAkon to sign APKs

## Permissions

- Storage permissions - to be able to save files to the same directory as a split APK (this is an option in the app, the storage permission will only be requested upon selecting it)
- QUERY_ALL_PACKAGES - to list apps installed on the device (see "Selecting from installed apps" in screenshots above)
- REQUEST_INSTALL_PACKAGES - to show an install button allowing prompt to install an app after merging it
- Internet permission - to check update for the app (can be disabled in settings)

Feel free to request a build of the app with any of these permissions removed.

## Client-side web prototype

This repository now includes a static browser prototype in `src/`. It runs the package inspection and merge pass in a Web Worker and does not call a backend service.

### Run

```sh
npm install
npm run dev
```

Then open the Vite local URL and drop or choose `.xapk`, `.apks`, `.apkm`, `.zip`, or `.apk` files.

### Build

```sh
npm run build
```

The built static site is written to `dist/`.

### GitHub Pages

The web app is deployable as a static GitHub Pages site. The workflow in `.github/workflows/pages.yml` runs on pushes to `redesign`, `main`, or `master`, installs dependencies with `npm ci`, builds with `npm run build`, and publishes the generated `dist/` directory.

Because GitHub Pages serves this repository under `/AntiSplit-Web/`, the Vite config uses that base path only in GitHub Actions. Local development and preview continue to use `/`.

### Fixture check

The current fixture command is:

```sh
npm run merge:fixture
```

The automated pass/fail gate is:

```sh
npm run verify:fixture
```

The full local parity gate is:

```sh
npm run verify:parity
```

It writes the latest step summary to `docs/parity-run.json` and runs the build, fixture checks, default and manifest corpus checks, standalone APK check, F-Droid APK corpus check, ARSC shape scan, environment check, Java/web comparisons, and completion audit.

To turn the generated evidence into a requirement-level completion report:

```sh
npm run audit:parity
```

It writes [`docs/parity-completion-audit.json`](docs/parity-completion-audit.json), including which requirements are proven, partial, or missing.

To capture local Android SDK tooling availability:

```sh
npm run verify:environment
```

It writes [`docs/environment-check.json`](docs/environment-check.json). This is the bounded check used to explain whether Android SDK `apksigner` validation can run locally.

Additional local samples can be batch-checked with:

```sh
npm run verify:corpus -- /path/to/apk-samples
```

Directories are scanned recursively for `.xapk`, `.apks`, `.apkm`, `.zip`, and `.apk` files.
With no path arguments, the runner uses the known local fixture corpus files that exist on this machine.

The current local sample list is also checked in as [`docs/local-corpus-manifest.txt`](docs/local-corpus-manifest.txt). To verify exactly that manifest:

```sh
npm run verify:corpus -- --manifest docs/local-corpus-manifest.txt --report docs/corpus-manifest-results.md
```

The available standalone APK path is verified separately:

```sh
npm run verify:standalone-corpus
```

To inventory a messy local folder before running verification:

```sh
npm run discover:corpus -- /path/to/downloads --report docs/corpus-inventory.md
```

This separates usable split containers and standalone APKs from generic ZIP files and unpacked config-split components. The report also writes a JSON companion when the path ends in `.md`.
Discovery skips heavyweight directories such as caches, `node_modules`, `Library`, and build outputs by default; pass `--include-ignored` for an exhaustive scan. APKs generated under this repository's `dist-fixtures/` directory are classified as `generated-output-apk` and are not counted as independent corpus samples.

To scan corpus resource-table shapes before or after a merge run:

```sh
npm run scan:arsc -- --manifest docs/local-corpus-manifest.txt --report docs/arsc-shape-report.md
```

This reports styled string pools, multi-package resource tables, and split type IDs that are absent from the base type string pool.

To write a Markdown corpus report:

```sh
npm run verify:corpus -- /path/to/apk-samples --report docs/corpus-results.md
```

When the report path ends in `.md`, the runner also writes a machine-readable companion JSON file next to it, such as `docs/corpus-results.json`.

By default, the corpus runner checks both `JAR/v1` and `JAR/v1 + v2` outputs, runs the bundled Java apksig verifier for the relevant Android platform range, runs Android SDK `apksigner` for v2/v3 outputs when available, and classifies warnings/failures as `resource-table`, `manifest`, `signing`, `zip-alignment`, `browser-platform`, or `general`. To narrow it while iterating:

```sh
npm run verify:corpus -- /path/to/apk-samples --signing=v1
npm run verify:corpus -- /path/to/apk-samples --signing=v2
```

The remaining parity work is tracked in [`docs/parity-plan.md`](docs/parity-plan.md), with a current requirement-by-requirement audit in [`docs/parity-audit.md`](docs/parity-audit.md) and machine-readable completion audit in [`docs/parity-completion-audit.json`](docs/parity-completion-audit.json). The current corpus baseline is in [`docs/corpus-results.md`](docs/corpus-results.md), and the local Downloads inventory is in [`docs/corpus-inventory.md`](docs/corpus-inventory.md).

The current local corpus baseline is two XAPK samples, REON POCKET and LibreLinkUp, both passing in `JAR/v1`, `JAR/v1 + v2`, `JAR/v1 + v2 + v3`, and `JAR/v1 + v2 + v3 + v4 sidecar` modes where applicable.

The targeted inventory across Downloads, Desktop, Documents, and this repository currently finds 20 usable independent samples out of 102 ZIP/APK-like files after excluding generated fixture APKs: 2 split containers, 1 local standalone APK, and 17 downloaded F-Droid standalone APKs. The standalone and F-Droid corpora are tracked in [`docs/corpus-standalone-results.md`](docs/corpus-standalone-results.md) and [`docs/fdroid-corpus-results.md`](docs/fdroid-corpus-results.md), and both pass the current signing modes.

Generated build and verification outputs are intentionally ignored by Git when they are bulky (`dist/`, `dist-fixtures/`, `node_modules/`). The checked-in `docs/` reports are lightweight evidence snapshots for the latest parity run.

The current resource-table shape scan is tracked in [`docs/arsc-shape-report.md`](docs/arsc-shape-report.md); it reports no styled string pools, multi-package tables, or split type IDs absent from the base type string pool for the two independent XAPK samples.

The local Java/REAndroid merge path can be compared against the web merger with:

```sh
npm run compare:java-web
```

This compiles `tools/java/CompareJavaMerge.java`, runs the local REAndroid merger on the REON fixture, generates unsigned and v1+v2 web outputs, and writes [`docs/java-web-comparison.md`](docs/java-web-comparison.md) plus a machine-readable [`docs/java-web-comparison.json`](docs/java-web-comparison.json) companion and sample-specific reports. The same tool can be run against another sample, for example:

```sh
npm run compare:java-web -- /path/to/sample.xapk
```

The current REON and LibreLinkUp comparisons show that the raw Java merge output carries the original APK Signing Block but its v2 digest no longer verifies after merging, while the web v1+v2 output has a newly generated v2 block that verifies with the browser verifier. The unsigned ZIP entry delta is now limited to Java's carried `META-INF/BNDLTOOL.*` signature files.

The guarded `resources.arsc` unsupported-scope checks can be run with:

```sh
npm run verify:arsc-guards
```

This mutates the REON resource split into styled-string-pool, multi-package, and missing-base-type-ID shapes and verifies that the browser merger rejects each one with a specific unsupported reason instead of producing a risky partial merge.

An experimental APK Signature Scheme v2 fixture path is available:

```sh
npm run verify:v2-fixture
```

It writes `dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit_v2.apk`, verifies that an APK Signing Block with exactly one fresh v2 pair is present, verifies that stale v3/v3.1/source-stamp pairs were not carried forward, recomputes the v2 content digest, and verifies the RSA/SHA-256 signature over v2 signed-data. It also compiles and runs the bundled Java `com.android.apksig.ApkVerifier` against the generated APK for Android 7.0+ verification, where v2 is supported. When Android SDK `apksigner` is available on PATH or under `ANDROID_HOME`/`ANDROID_SDK_ROOT`, the same command also runs `apksigner verify --verbose`. The v3/v4 follow-up scope is tracked in `docs/signing-v3-v4-feasibility.md`.

A minimal APK Signature Scheme v3 fixture path is available:

```sh
npm run verify:v3-fixture
```

It writes `dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit_v3.apk`, verifies fresh v2 and v3 pairs, recomputes the v3 content digest, verifies the RSA/SHA-256 signature over v3 signed-data, checks tamper-negative cases, compiles/runs bundled Java apksig for Android 9.0+ v3 verification, and runs Android SDK `apksigner verify --verbose` when available.

An APK Signature Scheme v4 sidecar fixture path is available:

```sh
npm run verify:v4-fixture
```

It writes `dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit_v4.apk` plus `dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit_v4.apk.idsig`, verifies the sidecar root hash, verity tree, APK digest, and RSA/SHA-256 signature in browser, checks tamper-negative cases, and compiles/runs bundled Java apksig with the sidecar.

The web UI exposes signing as:

- `JAR/v1` by default.
- `JAR/v1 + experimental v2` for browser-verified v2 output.
- `JAR/v1 + experimental v2/v3` for browser-verified v2 and minimal v3.0 output.
- `JAR/v1 + experimental v2/v3 + v4 sidecar` for browser-verified v2/v3 output plus a downloadable `.idsig`.
- `Unsigned` for workflows that will sign externally.

It uses `/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk` and writes:

```text
dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit.apk
```

Current observed result on June 13, 2026:

- Input: one base APK plus `config.armeabi_v7a.apk`, `config.en.apk`, and `config.mdpi.apk`.
- Output ZIP/APK: `23,308,826` bytes.
- Runtime through the shared merge core: about `7-8s` in Node on this machine for REON JAR/v1 output, including manifest cleanup, client-side JAR/v1 signing, resource-table diagnostics, and native-library alignment.
- `unzip -t dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit.apk` reports no compressed-data errors.
- `openssl pkcs7 -inform DER -in META-INF/ANTISPLT.RSA -print_certs` parses the generated signature block and reports a self-signed `AntiSplit Web Debug` certificate with serial `4153574542000001`.
- Browser-compatible verification reports:
  - `AndroidManifest.xml` exists and has an Android binary XML header.
  - At least one DEX file exists.
  - Existing JAR signature files were removed from `META-INF`.
  - New `META-INF/MANIFEST.MF`, `META-INF/ANTISPLT.SF`, and `META-INF/ANTISPLT.RSA` JAR/v1 signature files were added.
  - The two native library entries are stored uncompressed and 4096-byte aligned.
  - Two base-manifest split attributes, `requiredSplitTypes` and `splitTypes`, were removed.
  - Two base-manifest split meta-data elements, `com.android.vending.splits.required` and `com.android.vending.splits`, were removed.
  - Play split metadata XML such as `res/xml/splits0.xml` was removed.
- Resource-table diagnostics report:
  - Base APK: `365.0 KB resources.arsc`, 61 type config chunks, 3969 populated entries.
  - `config.mdpi.apk`: `29.4 KB resources.arsc`, 6 type config chunks, 201 populated entries, configs `default`, `mdpi`, `hdpi`, `xhdpi`, `anydpi`.
  - `config.en.apk`: `71.1 KB resources.arsc`, 5 type config chunks, 635 populated entries, configs `en-rCA`, `en-rGB`, `en-rXC`, `en-rIN`, `en-rAU`.
  - The browser merger rewrites package key string indices and table-level `TYPE_STRING` value indices, merges split strings into the base pools, merges type-spec flags, and appends 11 split type chunks.
  - Sparse and compact offset type chunks are handled by the same rewrite path; malformed chunks still fail closed.
  - Merged result: `451.7 KB resources.arsc`, 72 type config chunks, 4805 populated entries, table strings `1236->1570`, key strings `3806->3934`.
  - `config.mdpi.apk` required 161 used key-name remaps and 201 global string-pool remaps.
  - `config.en.apk` required 143 used key-name remaps and 269 global string-pool remaps.
- `npm run verify:fixture` asserts the package layout, package name, manifest/DEX presence, generated signature files, stale signature removal, native library compression/alignment, split manifest cleanup, parsable merged `resources.arsc`, expanded string-pool sizes, merged populated-entry count, and that no unsupported scope remains for this fixture.

### Current limitations

The web prototype is not yet feature-equivalent with the Android app:

- It now performs a guarded single-package `resources.arsc` merge for the tested REON and LibreLinkUp XAPK shapes, including sparse and compact offset type chunks plus complex map entries. More complex tables, styled string pools, multi-package resource tables, or type IDs absent from the base type string pool still fall back to an unsupported report.
- It now removes known split attributes, Play split meta-data elements, and `uses-split` manifest elements, but this is not yet a general-purpose binary manifest merger.
- It emits client-side JAR/v1 signature files by default and has experimental APK Signature Scheme v2, minimal v3.0, and v4 sidecar paths. The JAR/v1 fallback verifies with bundled Java apksig for Android 4.4-6.0. The v2 path verifies with the browser-side verifier, tamper-negative fixture checks, a guard that rejects stale v3/v3.1/source-stamp pairs, the bundled Java apksig verifier for Android 7.0+, corpus-level `apksigner` checks, and Android SDK `apksigner` from local build-tools 36.0.0. The v3 path verifies with the browser-side verifier, bundled Java apksig for Android 9.0+, and corpus-level `apksigner` checks. The v4 path generates a separate `.idsig` and verifies with the browser-side verifier and bundled Java apksig.
- The JAR/v1 signing path uses an embedded debug key converted from the Android app's existing `testkey.pk8`; it is suitable for generated test/debug APKs, not for preserving an app's original signing identity.
- It cannot select installed apps from an Android device or launch Android installation intents, because those are platform-only Android features.

The current environment check finds Java/Javac available, Android command-line tools under `/opt/homebrew/share/android-commandlinetools`, and Android SDK `apksigner` from build-tools 36.0.0. The next milestone is broad APK corpus testing against additional XAPK/APKS/APKM samples and corpus-driven resource-table coverage for styled strings, multi-package tables, and unusual type layouts.

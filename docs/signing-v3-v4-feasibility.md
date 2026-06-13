# APK Signature Scheme v3/v4 Feasibility

This note records what remains after the browser implementation added JAR/v1, APK Signature Scheme v2, minimal APK Signature Scheme v3.0 output, and APK Signature Scheme v4 sidecar export.

## Current Browser State

- `src/apkV2Signer.ts` can create a fresh APK Signing Block with one v2 pair (`0x7109871a`).
- `src/apkV2Verifier.ts` recomputes the v2 content digest and verifies the RSA/SHA-256 signature.
- `tools/verify-v2-fixture.ts` checks the generated v2 block, rejects content/signing-block tampering, and verifies with bundled Java apksig.
- `tools/compare-java-web.ts` shows the local Java merge output carries stale v2/v3/source-stamp material whose v2 digest no longer verifies, while the web v2 output has a fresh verifying v2 block.
- `src/apkV3Verifier.ts` and the `v1-v2-v3` signing mode implement minimal v3.0 signing with the debug key and no signing certificate lineage.
- `tools/verify-v3-fixture.ts` verifies the generated v2+v3 block in the browser, checks tamper-negative cases, and verifies v3 with bundled Java apksig for Android 9.0+.
- `src/apkV4Sidecar.ts` and the `v1-v2-v3-v4` signing mode generate a separate `.idsig` sidecar with hashing info, signing info, and a verity tree.
- `tools/verify-v4-fixture.ts` verifies the generated sidecar in the browser, checks tamper-negative cases, and verifies v4 with bundled Java apksig.

## v3

Local source reference: `app/src/main/java/com/android/apksig/internal/apk/v3`.

Relevant constants from `V3SchemeConstants.java`:

- v3 block ID: `0xf05368c0`.
- v3.1 block ID: `0x1b93ad61`.
- proof-of-rotation attribute ID: `0x3ba06f8c`.
- rotation-min-SDK attribute ID: `0x559f8b02`.
- rotation-on-development-release attribute ID: `0xc2a6b3ba`.

v3 is feasible client-side because it is still an APK Signing Block payload over APK sections that the browser code already rewrites for v2. The initial browser implementation covers a minimal v3.0 block. The local Java signer also has SDK-range fields, optional v3.1 block selection, proof-of-rotation attributes, and stripping-protection attributes, so broader v3 parity still has follow-up work:

1. Done: implement minimal single-signer v3.0 with no signing certificate lineage and the same debug key material used for v1/v2.
2. Done: add a v3 verifier that parses the v3 signer block, recomputes content digests, and verifies the signature for the generated single-SDK-range block.
3. Done: add fixture gates proving that v2-only and v2+v3 outputs are generated intentionally and that tampered v3 content fails verification.
4. Remaining: consider v3.1/proof-of-rotation only if the product needs key rotation semantics, because that requires extra signer metadata and compatibility checks beyond installability.

## v4

Local source reference: `app/src/main/java/com/android/apksig/internal/apk/v4`.

v4 is not embedded as another APK Signing Block pair. The local `V4SchemeSigner` generates a separate signature file containing hashing info, signing info, and the Merkle tree data used by incremental install flows. It first obtains a supported APK digest from v2 or v3, then computes a verity tree over the APK content and signs the v4 data.

For a browser download workflow, v4 is lower priority than v3 because downloading one installable APK does not use the Android incremental-install sidecar by itself. The browser implementation now covers sidecar generation and verification:

1. Done: keep producing the APK as the primary artifact.
2. Done: generate a separate `.idsig`/v4 sidecar download.
3. Done: add verifier tooling that validates the sidecar against the APK and bundled Java apksig.
4. Still platform-limited: browsers cannot invoke Android's incremental install APIs directly.

## Current Decision

Keep v3/v4 signing marked proven when the fixture and corpus gates pass. The remaining v4 limitation is not sidecar generation; it is that browsers still cannot launch Android's incremental install APIs directly.

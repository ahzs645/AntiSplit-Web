import { unzipSync, zipSync, strFromU8, type Zippable } from "fflate";
import { readBinaryManifestMinSdk, readBinaryManifestPackageName, sanitizeBinaryManifest } from "./androidBinaryXml";
import { readCentralDirectory, verifyMergedApk } from "./apkVerification";
import { createV1SignatureFiles } from "./apkV1Signer";
import { signApkWithV2DebugKey, signApkWithV2V3DebugKey } from "./apkV2Signer";
import { verifyV2Signature } from "./apkV2Verifier";
import { verifyV3Signature } from "./apkV3Verifier";
import { generateV4Sidecar, verifyV4Sidecar } from "./apkV4Sidecar";
import { analyzeApkResourceTable, analyzeResourceMergeCompatibility, summarizeArsc } from "./arscAnalyzer";
import { tryMergeResourceTables } from "./arscMerger";
import type { ApkEntrySummary, InspectResult, MergeOptions, MergeResult } from "./types";

type NamedBytes = {
  name: string;
  bytes: Uint8Array;
};

type ApkInput = NamedBytes & {
  role: "base" | "config" | "unknown";
  entries?: Record<string, Uint8Array>;
};

type ProgressSink = (message: string) => void;

const ZIP_CONTAINER_RE = /\.(xapk|apks|apkm|zip)$/i;
const APK_RE = /\.apk$/i;
const SIGNATURE_RE = /^META-INF\/(?:[^/]+\.(?:RSA|DSA|EC|SF)|MANIFEST\.MF)$/i;
const NO_COMPRESS_RE = /\.(?:arsc|so|png|jpg|jpeg|webp|gif|mp3|mp4|ogg|wav|3gp|apk)$/i;

export function inspectPackage(files: NamedBytes[]): InspectResult {
  const apks = collectApkInputs(files);
  const packageName = readXapkManifestPackage(files) ?? readBaseApkManifestPackage(apks);
  const apkEntries = apks.map(toSummary);
  const warnings: string[] = [];

  if (apks.length === 0) {
    warnings.push("No APK files were found in the selected input.");
  }
  if (!apks.some((apk) => apk.role === "base")) {
    warnings.push("No obvious base APK was found. The largest APK will be treated as the base during merge.");
  }
  if (apks.some((apk) => apk.role === "config")) {
    warnings.push("Config split APKs usually contain resources. The browser core will attempt a guarded resources.arsc merge and report unsupported cases if the table shape is outside the current implementation.");
  }

  return { packageName, apkEntries, warnings };
}

export function mergePackage(files: NamedBytes[], options: MergeOptions, progress: ProgressSink = () => {}): MergeResult {
  const logs: string[] = [];
  const warnings: string[] = [];
  const unsupported: string[] = [];
  const verification: string[] = [];
  const resourceDiagnostics: string[] = [];
  const log = (message: string) => {
    logs.push(message);
    progress(message);
  };
  const signingMode = normalizeSigningMode(options);

  log("Reading package");
  const apks = collectApkInputs(files);
  if (apks.length === 0) {
    throw new Error("No APK files found.");
  }

  const base = chooseBaseApk(apks);
  const selected = apks.filter((apk) => apk === base || options.includeSplits.includes(apk.name));
  log(`Found ${apks.length} APK file(s); selected ${selected.length}`);
  log(`Using ${base.name} as base APK`);

  for (const apk of selected) {
    apk.entries = unzipSync(apk.bytes);
    const resourceSummary = analyzeApkResourceTable(apk.bytes);
    if (resourceSummary) {
      resourceDiagnostics.push(`${apk.name}: ${summarizeArsc(resourceSummary)}`);
      for (const pkg of resourceSummary.packages) {
        const configs = [...new Set(pkg.typeChunks.map((chunk) => chunk.configQualifier))].join(", ");
        resourceDiagnostics.push(`${apk.name}: package ${pkg.name || pkg.id} has configs ${configs || "default"}`);
      }
    }
  }
  const resourceCompatibility = analyzeResourceMergeCompatibility(
    base.bytes,
    selected.filter((apk) => apk !== base).map((apk) => ({ name: apk.name, bytes: apk.bytes }))
  );
  const mergedEntries: Record<string, Uint8Array> = {};
  const baseEntries = base.entries ?? {};
  for (const [path, bytes] of Object.entries(baseEntries)) {
    if (!SIGNATURE_RE.test(path)) {
      mergedEntries[path] = bytes;
    }
  }

  const splitApks = selected.filter((apk) => apk !== base);
  const resourceMerge = tryMergeResourceTables(
    base.bytes,
    splitApks.map((apk) => ({ name: apk.name, bytes: apk.bytes }))
  );
  if (resourceMerge?.mergedBytes) {
    if (resourceCompatibility.reasons.length > 0) {
      resourceDiagnostics.push(...resourceCompatibility.reasons.map((reason) => `resources.arsc rewrite requirement: ${reason}`));
    }
    mergedEntries["resources.arsc"] = resourceMerge.mergedBytes;
    verification.push("Merged split resources.arsc tables into the base resource table.");
    resourceDiagnostics.push(...resourceMerge.diagnostics);
    const mergedResourceSummary = analyzeApkResourceTable(zipSync({ "resources.arsc": resourceMerge.mergedBytes }));
    if (mergedResourceSummary) {
      resourceDiagnostics.push(`merged resources.arsc: ${summarizeArsc(mergedResourceSummary)}`);
    }
  } else if (resourceMerge && resourceMerge.unsupported.length > 0) {
    resourceDiagnostics.push(...resourceMerge.diagnostics.map((line) => `resources.arsc merge blocker: ${line}`));
  } else if (resourceCompatibility.canAppendTypeChunks) {
    resourceDiagnostics.push("resources.arsc compatibility: split type chunks appear append-compatible with the base table.");
  } else {
    resourceDiagnostics.push(...resourceCompatibility.reasons.map((reason) => `resources.arsc merge blocker: ${reason}`));
  }

  if (mergedEntries["AndroidManifest.xml"]) {
    const manifestResult = sanitizeBinaryManifest(mergedEntries["AndroidManifest.xml"]);
    mergedEntries["AndroidManifest.xml"] = manifestResult.bytes;
    if (manifestResult.removedAttributes.length > 0) {
      log(`Removed ${manifestResult.removedAttributes.length} split manifest attribute(s)`);
      verification.push(`Removed manifest attributes: ${manifestResult.removedAttributes.join(", ")}`);
    }
    if (manifestResult.removedElements.length > 0) {
      log(`Removed ${manifestResult.removedElements.length} split manifest element(s)`);
      verification.push(`Removed manifest elements: ${manifestResult.removedElements.join(", ")}`);
    }
    if (manifestResult.remainingSplitElements.length > 0) {
      warnings.push(`Base manifest still contains split-related meta-data elements: ${manifestResult.remainingSplitElements.join(", ")}.`);
      unsupported.push("Full binary manifest element removal is incomplete; split meta-data elements may remain.");
    } else if (manifestResult.beforeMarkers.length > 0 && manifestResult.afterMarkers.length > 0) {
      verification.push("Known split manifest elements/attributes were removed; related strings remain only in the manifest string pool.");
    } else if (manifestResult.beforeMarkers.length > 0) {
      verification.push("Known split markers were removed from the base binary manifest.");
    } else {
      verification.push("No known split markers detected in the base binary manifest.");
    }
  }

  const copied: string[] = [];
  const skipped: string[] = [];
  const conflictPaths = new Set<string>();
  for (const split of selected) {
    if (split === base) {
      continue;
    }
    log(`Merging payload from ${split.name}`);
    const entries = split.entries ?? {};
    for (const [path, bytes] of Object.entries(entries)) {
      if (SIGNATURE_RE.test(path)) {
        skipped.push(`${split.name}:${path}`);
        continue;
      }
      if (path === "AndroidManifest.xml" || path === "resources.arsc") {
        if (path === "resources.arsc" && resourceMerge?.mergedBytes) {
          skipped.push(`${split.name}:${path}`);
          continue;
        }
        conflictPaths.add(path);
        skipped.push(`${split.name}:${path}`);
        continue;
      }
      if (mergedEntries[path]) {
        conflictPaths.add(path);
        skipped.push(`${split.name}:${path}`);
        continue;
      }
      mergedEntries[path] = bytes;
      copied.push(`${split.name}:${path}`);
    }
  }

  if (conflictPaths.has("resources.arsc")) {
    if (resourceMerge?.unsupported.length) {
      unsupported.push(...resourceMerge.unsupported.map((reason) => `resources.arsc: ${reason}`));
    } else {
      const splitResourceDiagnostics = resourceDiagnostics.filter((line) => !line.startsWith(`${base.name}:`));
      unsupported.push(
        `Full resources.arsc merge is not implemented in the browser core yet; ${splitResourceDiagnostics.length} split resource-table diagnostic line(s) were recorded.`
      );
    }
  }
  if (conflictPaths.has("AndroidManifest.xml")) {
    warnings.push("Split AndroidManifest.xml files were skipped after the base manifest sanitization pass.");
  }
  if (signingMode === "none") {
    warnings.push("Output is unsigned. Android will not install unsigned APKs without external signing or patched package verification.");
  }

  log(`Copied ${copied.length} non-conflicting split payload entr${copied.length === 1 ? "y" : "ies"}`);
  if (skipped.length > 0) {
    log(`Skipped ${skipped.length} signature, manifest, resource, or conflicting entr${skipped.length === 1 ? "y" : "ies"}`);
  }

  if (signingMode === "v1" || signingMode === "v1-v2" || signingMode === "v1-v2-v3" || signingMode === "v1-v2-v3-v4") {
    log("Signing APK with client-side JAR/v1 signature");
    const manifestMinSdk = mergedEntries["AndroidManifest.xml"] ? readBinaryManifestMinSdk(mergedEntries["AndroidManifest.xml"]) ?? 1 : null;
    const v1DigestAlgorithm = manifestMinSdk !== null && manifestMinSdk < 18 ? "sha1" : "sha256";
    const signatureFiles = createV1SignatureFiles(mergedEntries, { digestAlgorithm: v1DigestAlgorithm });
    mergedEntries["META-INF/MANIFEST.MF"] = signatureFiles.manifest;
    mergedEntries["META-INF/ANTISPLT.SF"] = signatureFiles.signatureFile;
    mergedEntries["META-INF/ANTISPLT.RSA"] = signatureFiles.signatureBlock;
    verification.push(`Added client-side JAR/v1 APK signature files (${v1DigestAlgorithm.toUpperCase()} digest${manifestMinSdk !== null ? `, minSdk ${manifestMinSdk}` : ""}).`);
    verification.push(`Generated debug X.509 certificate (${signatureFiles.certificateDer.byteLength} bytes).`);
    if (signingMode === "v1") {
      warnings.push("APK Signature Scheme v2/v3 signing is not enabled for this output; it uses JAR/v1 signing only.");
    }
  }

  log("Writing APK zip");
  let apkBytes = writeAlignedApk(mergedEntries, normalizeCompressionLevel(options.compressionLevel), log);
  if (signingMode === "v1-v2" || signingMode === "v1-v2-v3" || signingMode === "v1-v2-v3-v4") {
    log("Adding experimental APK Signature Scheme v2 block");
    const v2Result = signingMode === "v1-v2-v3" || signingMode === "v1-v2-v3-v4" ? signApkWithV2V3DebugKey(apkBytes) : signApkWithV2DebugKey(apkBytes);
    apkBytes = v2Result.apkBytes;
    const v2Verification = verifyV2Signature(apkBytes);
    if (v2Verification.verified) {
      verification.push(`Added APK Signature Scheme v2 block (${v2Result.signingBlockSize} bytes, ${v2Verification.signers} signer).`);
      verification.push("Verified v2 content digest and RSA/SHA-256 signature in browser.");
    } else {
      warnings.push(`Experimental APK Signature Scheme v2 self-verification failed: ${v2Verification.warnings.join("; ") || "unknown failure"}.`);
      unsupported.push("Experimental APK Signature Scheme v2 output could not be internally verified.");
    }
    warnings.push("APK Signature Scheme v2 is generated client-side and verified by the fixture/parity gates.");
    if (signingMode === "v1-v2-v3" || signingMode === "v1-v2-v3-v4") {
      const v3Verification = verifyV3Signature(apkBytes);
      if (v3Verification.verified) {
        verification.push(`Added APK Signature Scheme v3 block (${v3Verification.signers} signer).`);
        verification.push("Verified v3 content digest and RSA/SHA-256 signature in browser.");
      } else {
        warnings.push(`Experimental APK Signature Scheme v3 self-verification failed: ${v3Verification.warnings.join("; ") || "unknown failure"}.`);
        unsupported.push("Experimental APK Signature Scheme v3 output could not be internally verified.");
      }
      warnings.push("APK Signature Scheme v3 is generated client-side and verified by the fixture/parity gates.");
    }
  }
  let v4SidecarBytes: Uint8Array | undefined;
  if (signingMode === "v1-v2-v3-v4") {
    log("Generating APK Signature Scheme v4 sidecar");
    const v4Result = generateV4Sidecar(apkBytes);
    v4SidecarBytes = v4Result.idsigBytes;
    const v4Verification = verifyV4Sidecar(apkBytes, v4SidecarBytes);
    if (v4Verification.verified) {
      verification.push(`Generated APK Signature Scheme v4 sidecar (${v4SidecarBytes.byteLength} bytes, ${v4Result.treeBytes.byteLength} bytes verity tree).`);
      verification.push("Verified v4 sidecar root hash, verity tree, APK digest, and RSA/SHA-256 signature in browser.");
    } else {
      warnings.push(`Experimental APK Signature Scheme v4 sidecar self-verification failed: ${v4Verification.warnings.join("; ") || "unknown failure"}.`);
      unsupported.push("Experimental APK Signature Scheme v4 sidecar could not be internally verified.");
    }
    warnings.push("APK Signature Scheme v4 sidecar is experimental and only useful for Android incremental-install workflows.");
  }
  verification.push(`Output contains ${Object.keys(mergedEntries).length} ZIP entries before final APK serialization.`);
  verification.push("Native libraries and common already-compressed assets are stored without deflate compression.");
  const apkVerification = verifyMergedApk(apkBytes);
  verification.push(...apkVerification.passed);
  warnings.push(...apkVerification.warnings);

  return {
    fileName: buildOutputName(files),
    apkBytes,
    v4SidecarFileName: v4SidecarBytes ? `${buildOutputName(files)}.idsig` : undefined,
    v4SidecarBytes,
    logs,
    warnings,
    unsupported,
    verification,
    resourceDiagnostics
  };
}

function normalizeSigningMode(options: MergeOptions): NonNullable<MergeOptions["signingMode"]> {
  if (options.signingMode) {
    return options.signingMode;
  }
  return options.signApk ? "v1" : "none";
}

function collectApkInputs(files: NamedBytes[]): ApkInput[] {
  const apks: ApkInput[] = [];

  for (const file of files) {
    if (APK_RE.test(file.name)) {
      apks.push({ ...file, role: roleForApk(file.name, file.bytes.length) });
      continue;
    }

    if (!ZIP_CONTAINER_RE.test(file.name)) {
      continue;
    }

    const entries = unzipSync(file.bytes);
    for (const [entryName, bytes] of Object.entries(entries)) {
      if (APK_RE.test(entryName)) {
        apks.push({
          name: entryName,
          bytes,
          role: roleForApk(entryName, bytes.length)
        });
      }
    }
  }

  return apks.sort((a, b) => {
    if (a.role !== b.role) {
      return a.role === "base" ? -1 : b.role === "base" ? 1 : 0;
    }
    return b.bytes.length - a.bytes.length;
  });
}

function chooseBaseApk(apks: ApkInput[]): ApkInput {
  return apks.find((apk) => apk.role === "base") ?? [...apks].sort((a, b) => b.bytes.length - a.bytes.length)[0];
}

function roleForApk(name: string, size: number): ApkInput["role"] {
  const basename = name.split("/").pop() ?? name;
  if (basename === "base.apk" || (!basename.startsWith("config.") && !basename.startsWith("split.") && size > 1024 * 1024)) {
    return "base";
  }
  if (basename.startsWith("config.") || basename.startsWith("split.")) {
    return "config";
  }
  return "unknown";
}

function toSummary(apk: ApkInput): ApkEntrySummary {
  const warnings: string[] = [];
  const resourceSummary = analyzeApkResourceTable(apk.bytes);
  if (apk.role === "config") {
    warnings.push(resourceSummary ? "Requires resource-table merge." : "May require resource-table merge.");
  }
  return {
    name: apk.name,
    size: apk.bytes.length,
    role: apk.role,
    selected: true,
    warnings,
    resourceTable: resourceSummary ? summarizeArsc(resourceSummary) : undefined
  };
}

function readXapkManifestPackage(files: NamedBytes[]): string | null {
  for (const file of files) {
    if (!ZIP_CONTAINER_RE.test(file.name)) {
      continue;
    }
    try {
      const entries = unzipSync(file.bytes);
      const manifest = entries["manifest.json"];
      if (!manifest) {
        continue;
      }
      const json = JSON.parse(strFromU8(manifest));
      return typeof json.package_name === "string" ? json.package_name : null;
    } catch {
      return null;
    }
  }
  return null;
}

function readBaseApkManifestPackage(apks: ApkInput[]): string | null {
  const base = apks.length > 0 ? chooseBaseApk(apks) : null;
  if (!base) {
    return null;
  }
  try {
    const entries = unzipSync(base.bytes, {
      filter: (entry) => entry.name === "AndroidManifest.xml"
    });
    const manifest = entries["AndroidManifest.xml"];
    return manifest ? readBinaryManifestPackageName(manifest) : null;
  } catch {
    return null;
  }
}

function normalizeCompressionLevel(level: number): 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 {
  if (!Number.isFinite(level)) {
    return 6;
  }
  return Math.max(0, Math.min(9, Math.round(level))) as 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
}

function buildOutputName(files: NamedBytes[]): string {
  const first = files[0]?.name ?? "merged.apk";
  return first.replace(/\.(?:xapk|apks|apkm|zip|apk)$/i, "_antisplit.apk");
}

function writeAlignedApk(
  entries: Record<string, Uint8Array>,
  defaultLevel: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9,
  log: ProgressSink
): Uint8Array {
  const padding = new Map<string, number>();
  let apkBytes = zipSync(toZippable(entries, defaultLevel, padding));
  const unpaddedEntries = readCentralDirectory(apkBytes);
  let cumulativePadding = 0;

  for (const entry of unpaddedEntries) {
    if (!/^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)) {
      continue;
    }
    const requiredPadding = (4096 - ((entry.dataOffset + cumulativePadding) % 4096)) % 4096;
    if (requiredPadding !== 0) {
      const totalExtraLength = requiredPadding >= 4 ? requiredPadding : requiredPadding + 4096;
      padding.set(entry.name, totalExtraLength);
      cumulativePadding += totalExtraLength;
    }
  }

  if (padding.size > 0) {
    apkBytes = zipSync(toZippable(entries, defaultLevel, padding));
  }

  for (let pass = 0; pass < 4; pass++) {
    const zipEntries = readCentralDirectory(apkBytes);
    let changed = false;

    for (const entry of zipEntries) {
      if (!/^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)) {
        continue;
      }
      const requiredPadding = (4096 - (entry.dataOffset % 4096)) % 4096;
      if (requiredPadding !== 0) {
        const currentPadding = padding.get(entry.name) ?? 0;
        const totalExtraLength = requiredPadding >= 4 ? requiredPadding : requiredPadding + 4096;
        padding.set(entry.name, currentPadding + totalExtraLength);
        changed = true;
      }
    }

    if (!changed) {
      if (padding.size > 0) {
        log(`Aligned ${padding.size} native librar${padding.size === 1 ? "y" : "ies"} on 4096-byte boundaries`);
      }
      return apkBytes;
    }

    apkBytes = zipSync(toZippable(entries, defaultLevel, padding));
  }

  log("Native library alignment did not converge after 64 passes");
  return apkBytes;
}

function toZippable(
  entries: Record<string, Uint8Array>,
  defaultLevel: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9,
  padding: Map<string, number>
): Zippable {
  const zippable: Zippable = {};
  for (const [path, bytes] of Object.entries(entries)) {
    const extraPadding = padding.get(path) ?? 0;
    zippable[path] = [
      bytes,
      {
        level: shouldStore(path) ? 0 : defaultLevel,
        extra: extraPadding > 0 ? { 0xd935: new Uint8Array(extraFieldPayloadLength(extraPadding)) } : undefined
      }
    ];
  }
  return zippable;
}

function shouldStore(path: string): boolean {
  return path === "AndroidManifest.xml" || NO_COMPRESS_RE.test(path);
}

function extraFieldPayloadLength(totalPadding: number): number {
  return totalPadding - 4;
}

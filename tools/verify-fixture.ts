import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { unzipSync } from "fflate";
import { inspectPackage, mergePackage } from "../src/mergeCore";
import { inspectApkSigningBlock, readCentralDirectory, verifyMergedApk } from "../src/apkVerification";
import { analyzeResourceTable } from "../src/arscAnalyzer";
import { verifyWithBundledApkSig } from "./java-apksig";

const fixturePath = process.argv[2] ?? "/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk";
const bytes = await readFile(fixturePath);
const input = [{ name: basename(fixturePath), bytes: new Uint8Array(bytes) }];
const inspect = inspectPackage(input);
const started = performance.now();
const result = mergePackage(input, {
  includeSplits: inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name),
  compressionLevel: 6,
  signApk: true
});
const elapsedMs = Math.round(performance.now() - started);
const entries = readCentralDirectory(result.apkBytes);
const entryNames = new Set(entries.map((entry) => entry.name));
const apkVerification = verifyMergedApk(result.apkBytes);
const signingBlock = inspectApkSigningBlock(result.apkBytes);
const javaPreNVerificationPath = join("dist-fixtures", "REON_fixture_v1_for_java_apksig.apk");
await mkdir("dist-fixtures", { recursive: true });
await writeFile(javaPreNVerificationPath, result.apkBytes);
const javaPreNVerification = await verifyWithBundledApkSig(javaPreNVerificationPath, 19, 23);
const outputZipEntries = unzipSync(result.apkBytes, {
  filter: (file) => file.name === "resources.arsc"
});
const outputResourceSummary = outputZipEntries["resources.arsc"] ? analyzeResourceTable(outputZipEntries["resources.arsc"]) : null;
const outputPackage = outputResourceSummary?.packages[0];
const outputPopulatedEntries = outputPackage?.typeChunks.reduce((sum, chunk) => sum + chunk.populatedEntries, 0) ?? 0;

const assertions: Array<[string, boolean, string]> = [
  ["inspect finds four APK entries", inspect.apkEntries.length === 4, `${inspect.apkEntries.length} entries found`],
  ["base package name is detected", inspect.packageName === "jp.co.sony.reonpocket", String(inspect.packageName)],
  ["output contains AndroidManifest.xml", entryNames.has("AndroidManifest.xml"), "missing AndroidManifest.xml"],
  ["output contains DEX files", entries.some((entry) => /^classes\d*\.dex$/.test(entry.name)), "no classes*.dex entries"],
  ["generated v1 signature files are present", ["META-INF/MANIFEST.MF", "META-INF/ANTISPLT.SF", "META-INF/ANTISPLT.RSA"].every((name) => entryNames.has(name)), "signature entries missing"],
  [
    "bundled Java apksig verifies v1 fallback for pre-Android-7",
    javaPreNVerification.available && javaPreNVerification.ok && javaPreNVerification.verifiedUsingV1 === true,
    [...(javaPreNVerification.errors ?? []), javaPreNVerification.stderr].filter(Boolean).join("; ")
  ],
  ["APK Signing Block detector reports no v2 block yet", !signingBlock.present, signingBlock.pairs.map((pair) => pair.name).join(", ")],
  ["stale BNDLTOOL signatures are removed", !entryNames.has("META-INF/BNDLTOOL.SF") && !entryNames.has("META-INF/BNDLTOOL.RSA"), "stale BNDLTOOL signature remains"],
  ["native libraries are uncompressed", entries.filter((entry) => /^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)).every((entry) => entry.method === 0), "compressed native library found"],
  ["native libraries are 4096-byte aligned", entries.filter((entry) => /^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)).every((entry) => entry.dataOffset % 4096 === 0), "unaligned native library found"],
  ["split manifest attributes were removed", result.verification.some((line) => line.includes("requiredSplitTypes") && line.includes("splitTypes")), "attribute removal not reported"],
  ["split manifest elements were removed", result.verification.some((line) => line.includes("com.android.vending.splits.required") && line.includes("com.android.vending.splits")), "element removal not reported"],
  ["Play split metadata XML payload is preserved for resource-table consistency", entryNames.has("res/xml/splits0.xml"), "res/xml/splits0.xml missing"],
  ["resource diagnostics identify config.mdpi resources", result.resourceDiagnostics.some((line) => line.includes("config.mdpi.apk") && line.includes("201 populated entries")), "config.mdpi resources not diagnosed"],
  ["resource diagnostics identify config.en resources", result.resourceDiagnostics.some((line) => line.includes("config.en.apk") && line.includes("635 populated entries")), "config.en resources not diagnosed"],
  ["resource diagnostics explain config.mdpi rewrite requirement", result.resourceDiagnostics.some((line) => line.includes("config.mdpi.apk") && line.includes("string pool differs")), "config.mdpi rewrite requirement not diagnosed"],
  ["resource diagnostics explain config.en rewrite requirement", result.resourceDiagnostics.some((line) => line.includes("config.en.apk") && line.includes("string pool differs")), "config.en rewrite requirement not diagnosed"],
  ["resource diagnostics identify config.mdpi value string remapping", result.resourceDiagnostics.some((line) => line.includes("config.mdpi.apk") && line.includes("201 resource value string(s) need global string-pool remapping")), "config.mdpi value string remapping not diagnosed"],
  ["resource diagnostics identify config.en value string remapping", result.resourceDiagnostics.some((line) => line.includes("config.en.apk") && line.includes("269 resource value string(s) need global string-pool remapping")), "config.en value string remapping not diagnosed"],
  ["resources.arsc merge is reported", result.verification.some((line) => line.includes("Merged split resources.arsc")), "resource merge verification not reported"],
  ["merged resources.arsc is parsable", Boolean(outputResourceSummary && outputResourceSummary.packageCount === 1 && outputResourceSummary.warnings.length === 0), outputResourceSummary?.warnings.join("; ") ?? "missing resources.arsc"],
  ["merged resources.arsc includes split entries", outputPopulatedEntries === 4805, `${outputPopulatedEntries} populated entries found`],
  ["merged resources.arsc includes expanded string pools", Boolean(outputResourceSummary && outputResourceSummary.tableStrings.length === 1570 && outputPackage && outputPackage.keyCount === 3934), `table strings ${outputResourceSummary?.tableStrings.length ?? 0}, key count ${outputPackage?.keyCount ?? 0}`],
  ["no unsupported resource scope remains", result.unsupported.length === 0, result.unsupported.join("; ")],
  ["APK verifier has no structural warnings", apkVerification.warnings.length === 0, apkVerification.warnings.join("; ")]
];

const failed = assertions.filter(([, ok]) => !ok);
for (const [label, ok, detail] of assertions) {
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok ? "" : `: ${detail}`}`);
}

console.log(
  JSON.stringify(
    {
      fixturePath,
      outputBytes: result.apkBytes.byteLength,
      elapsedMs,
      warnings: result.warnings,
      unsupported: result.unsupported,
      javaPreNVerification: {
        available: javaPreNVerification.available,
        ok: javaPreNVerification.ok,
        verified: javaPreNVerification.verified,
        verifiedUsingV1: javaPreNVerification.verifiedUsingV1,
        signerCertificateCount: javaPreNVerification.signerCertificateCount,
        v1SignerCount: javaPreNVerification.v1SignerCount,
        errorCount: javaPreNVerification.errors?.length ?? 0,
        warningCount: javaPreNVerification.warnings?.length ?? 0
      },
      verificationCount: result.verification.length,
      resourceDiagnosticCount: result.resourceDiagnostics.length
    },
    null,
    2
  )
);

if (failed.length > 0) {
  process.exitCode = 1;
}

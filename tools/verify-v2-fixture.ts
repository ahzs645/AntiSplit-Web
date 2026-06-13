import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { inspectPackage, mergePackage } from "../src/mergeCore";
import { inspectApkSigningBlock, readCentralDirectory, verifyMergedApk } from "../src/apkVerification";
import { verifyV2Signature } from "../src/apkV2Verifier";
import { verifyWithApkSigner } from "./apksigner";
import { verifyWithBundledApkSig } from "./java-apksig";

const fixturePath = process.argv[2] ?? "/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk";
const bytes = await readFile(fixturePath);
const input = [{ name: basename(fixturePath), bytes: new Uint8Array(bytes) }];
const inspect = inspectPackage(input);
const merged = mergePackage(input, {
  includeSplits: inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name),
  compressionLevel: 6,
  signApk: true,
  signingMode: "v1-v2"
});
const signingBlock = inspectApkSigningBlock(merged.apkBytes);
const v2Verification = verifyV2Signature(merged.apkBytes);
const tamperedContent = new Uint8Array(merged.apkBytes);
tamperedContent[0] ^= 0xff;
const tamperedContentVerification = verifyV2Signature(tamperedContent);
const tamperedSigningBlock = new Uint8Array(merged.apkBytes);
if (signingBlock.present && typeof signingBlock.offset === "number") {
  tamperedSigningBlock[signingBlock.offset + 20] ^= 0x01;
}
const tamperedSigningBlockVerification = verifyV2Signature(tamperedSigningBlock);
const verification = verifyMergedApk(merged.apkBytes);
const entries = readCentralDirectory(merged.apkBytes);
const outputPath = join("dist-fixtures", `${basename(fixturePath).replace(/\.(xapk|apks|apkm|zip|apk)$/i, "")}_antisplit_v2.apk`);
await mkdir("dist-fixtures", { recursive: true });
await writeFile(outputPath, merged.apkBytes);
const javaApkSig = await verifyWithBundledApkSig(outputPath, 24, 35);
const apkSigner = await verifyWithApkSigner(outputPath);

const assertions: Array<[string, boolean, string]> = [
  ["v2 signing block is present", signingBlock.present, "missing APK Signing Block"],
  ["v2 pair is present", signingBlock.pairs.some((pair) => pair.idHex === "0x7109871a"), signingBlock.pairs.map((pair) => pair.idHex).join(", ")],
  [
    "v2 block contains no stale v3/v3.1/source-stamp pairs",
    signingBlock.pairs.length === 1 && signingBlock.pairs[0]?.idHex === "0x7109871a",
    signingBlock.pairs.map((pair) => `${pair.name} (${pair.idHex})`).join(", ")
  ],
  ["v2 content digest and RSA signature verify", v2Verification.verified, v2Verification.warnings.join("; ")],
  [
    "tampered APK content fails v2 verification",
    !tamperedContentVerification.verified && tamperedContentVerification.warnings.some((warning) => warning.includes("digest")),
    tamperedContentVerification.warnings.join("; ")
  ],
  [
    "tampered v2 signing block fails v2 verification",
    !tamperedSigningBlockVerification.verified,
    tamperedSigningBlockVerification.warnings.join("; ")
  ],
  ["central directory remains readable", entries.length > 0, "no central-directory entries"],
  ["APK verifier has no structural warnings", verification.warnings.length === 0, verification.warnings.join("; ")]
];
if (javaApkSig.available) {
  assertions.push([
    "bundled Java apksig verifies APK using v2 for Android 7.0+",
    javaApkSig.ok && javaApkSig.verifiedUsingV2 === true,
    [...(javaApkSig.errors ?? []), ...(javaApkSig.warnings ?? []), javaApkSig.stderr].filter(Boolean).join("; ")
  ]);
}
if (apkSigner.available) {
  assertions.push(["Android apksigner verifies APK", apkSigner.ok, apkSigner.stderr || apkSigner.stdout]);
}

const failed = assertions.filter(([, ok]) => !ok);
for (const [label, ok, detail] of assertions) {
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok ? "" : `: ${detail}`}`);
}

console.log(
  JSON.stringify(
    {
      fixturePath,
      outputPath,
      outputBytes: merged.apkBytes.byteLength,
      signingBlock,
      v2Verification,
      tamperedContentVerification,
      tamperedSigningBlockVerification,
      javaApkSig,
      apkSigner
    },
    null,
    2
  )
);

if (failed.length > 0) {
  process.exitCode = 1;
}

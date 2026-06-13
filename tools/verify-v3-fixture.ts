import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { inspectPackage, mergePackage } from "../src/mergeCore";
import { inspectApkSigningBlock, readCentralDirectory, verifyMergedApk } from "../src/apkVerification";
import { verifyV2Signature } from "../src/apkV2Verifier";
import { verifyV3Signature } from "../src/apkV3Verifier";
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
  signingMode: "v1-v2-v3"
});
const signingBlock = inspectApkSigningBlock(merged.apkBytes);
const v2Verification = verifyV2Signature(merged.apkBytes);
const v3Verification = verifyV3Signature(merged.apkBytes);
const tamperedContent = new Uint8Array(merged.apkBytes);
tamperedContent[0] ^= 0xff;
const tamperedV3ContentVerification = verifyV3Signature(tamperedContent);
const tamperedSigningBlock = new Uint8Array(merged.apkBytes);
if (signingBlock.present && typeof signingBlock.offset === "number") {
  const v2Pair = signingBlock.pairs.find((pair) => pair.idHex === "0x7109871a");
  const v3PayloadOffset = signingBlock.offset + 8 + (v2Pair ? 8 + 4 + v2Pair.size : 0) + 8 + 4;
  tamperedSigningBlock[v3PayloadOffset + 20] ^= 0x01;
}
const tamperedV3SigningBlockVerification = verifyV3Signature(tamperedSigningBlock);
const verification = verifyMergedApk(merged.apkBytes);
const entries = readCentralDirectory(merged.apkBytes);
const outputPath = join("dist-fixtures", `${basename(fixturePath).replace(/\.(xapk|apks|apkm|zip|apk)$/i, "")}_antisplit_v3.apk`);
await mkdir("dist-fixtures", { recursive: true });
await writeFile(outputPath, merged.apkBytes);
const javaApkSig = await verifyWithBundledApkSig(outputPath, 28, 35);
const apkSigner = await verifyWithApkSigner(outputPath);

const pairIds = signingBlock.pairs.map((pair) => pair.idHex).sort();
const assertions: Array<[string, boolean, string]> = [
  ["APK Signing Block is present", signingBlock.present, "missing APK Signing Block"],
  ["v2 and v3 pairs are present", pairIds.length === 2 && pairIds[0] === "0x7109871a" && pairIds[1] === "0xf05368c0", signingBlock.pairs.map((pair) => `${pair.name} (${pair.idHex})`).join(", ")],
  ["v2 content digest and RSA signature verify", v2Verification.verified, v2Verification.warnings.join("; ")],
  ["v3 content digest and RSA signature verify", v3Verification.verified, v3Verification.warnings.join("; ")],
  [
    "tampered APK content fails v3 verification",
    !tamperedV3ContentVerification.verified && tamperedV3ContentVerification.warnings.some((warning) => warning.includes("digest")),
    tamperedV3ContentVerification.warnings.join("; ")
  ],
  [
    "tampered v3 signing block fails v3 verification",
    !tamperedV3SigningBlockVerification.verified,
    tamperedV3SigningBlockVerification.warnings.join("; ")
  ],
  ["central directory remains readable", entries.length > 0, "no central-directory entries"],
  ["APK verifier has no structural warnings", verification.warnings.length === 0, verification.warnings.join("; ")]
];
if (javaApkSig.available) {
  assertions.push([
    "bundled Java apksig verifies APK using v3 for Android 9.0+",
    javaApkSig.ok && javaApkSig.verifiedUsingV3 === true,
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
      v3Verification,
      tamperedV3ContentVerification,
      tamperedV3SigningBlockVerification,
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

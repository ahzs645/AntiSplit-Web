import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { inspectPackage, mergePackage } from "../src/mergeCore";
import { generateV4Sidecar, verifyV4Sidecar } from "../src/apkV4Sidecar";
import { verifyWithBundledApkSig } from "./java-apksig";

const fixturePath = process.argv[2] ?? "/Users/ahmadjalil/Downloads/iHunter+BC_5.0.69_APKPure.xapk";
const bytes = await readFile(fixturePath);
const input = [{ name: basename(fixturePath), bytes: new Uint8Array(bytes) }];
const inspect = inspectPackage(input);
const merged = mergePackage(input, {
  includeSplits: inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name),
  compressionLevel: 6,
  signApk: true,
  signingMode: "v1-v2-v3"
});
const v4 = generateV4Sidecar(merged.apkBytes);
const v4Verification = verifyV4Sidecar(merged.apkBytes, v4.idsigBytes);
const tamperedApk = new Uint8Array(merged.apkBytes);
tamperedApk[0] ^= 0xff;
const tamperedApkVerification = verifyV4Sidecar(tamperedApk, v4.idsigBytes);
const tamperedSidecar = new Uint8Array(v4.idsigBytes);
tamperedSidecar[Math.max(0, tamperedSidecar.length - 16)] ^= 0xff;
const tamperedSidecarVerification = verifyV4Sidecar(merged.apkBytes, tamperedSidecar);

const outputBase = basename(fixturePath).replace(/\.(xapk|apks|apkm|zip|apk)$/i, "");
const apkPath = join("dist-fixtures", `${outputBase}_antisplit_v4.apk`);
const idsigPath = join("dist-fixtures", `${outputBase}_antisplit_v4.apk.idsig`);
await mkdir("dist-fixtures", { recursive: true });
await writeFile(apkPath, merged.apkBytes);
await writeFile(idsigPath, v4.idsigBytes);
const javaApkSig = await verifyWithBundledApkSig(apkPath, 28, 35, idsigPath);

const assertions: Array<[string, boolean, string]> = [
  ["v4 sidecar is generated", v4.idsigBytes.length > 0, "empty idsig"],
  ["v4 sidecar contains verity tree", v4.treeBytes.length > 0, "empty verity tree"],
  ["browser verifies v4 sidecar", v4Verification.verified, v4Verification.warnings.join("; ")],
  [
    "tampered APK content fails v4 verification",
    !tamperedApkVerification.verified && tamperedApkVerification.warnings.some((warning) => warning.includes("digest") || warning.includes("root") || warning.includes("tree")),
    tamperedApkVerification.warnings.join("; ")
  ],
  [
    "tampered v4 sidecar fails verification",
    !tamperedSidecarVerification.verified,
    tamperedSidecarVerification.warnings.join("; ")
  ]
];
if (javaApkSig.available) {
  assertions.push([
    "bundled Java apksig verifies APK using v4 sidecar",
    javaApkSig.ok && javaApkSig.verifiedUsingV4 === true,
    [...(javaApkSig.errors ?? []), ...(javaApkSig.warnings ?? []), javaApkSig.stderr].filter(Boolean).join("; ")
  ]);
}

const failed = assertions.filter(([, ok]) => !ok);
for (const [label, ok, detail] of assertions) {
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok ? "" : `: ${detail}`}`);
}

console.log(
  JSON.stringify(
    {
      fixturePath,
      apkPath,
      idsigPath,
      apkBytes: merged.apkBytes.byteLength,
      idsigBytes: v4.idsigBytes.byteLength,
      treeBytes: v4.treeBytes.byteLength,
      rootHashHex: toHex(v4.rootHash),
      apkDigestHex: toHex(v4.apkDigest),
      v4Verification,
      tamperedApkVerification,
      tamperedSidecarVerification,
      javaApkSig
    },
    null,
    2
  )
);

if (failed.length > 0) {
  process.exitCode = 1;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

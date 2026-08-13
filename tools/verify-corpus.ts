import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { inspectPackage, mergePackage } from "../src/mergeCore";
import { inspectApkSigningBlock, readCentralDirectory, verifyMergedApk } from "../src/apkVerification";
import { verifyWithBundledApkSig } from "./java-apksig";
import { verifyWithApkSigner } from "./apksigner";
import type { MergeOptions } from "../src/types";

type SigningMode = "v1" | "v2" | "v3" | "v4" | "both" | "all";

type SigningResult = {
  mode: "v1" | "v1-v2" | "v1-v2-v3" | "v1-v2-v3-v4";
  ok: boolean;
  outputBytes?: number;
  elapsedMs?: number;
  signingBlock: string;
  javaApkSig: string;
  apkSigner: string;
  classifications: string[];
  warnings: string[];
  unsupported: string[];
  failures: string[];
};

type CorpusResult = {
  path: string;
  ok: boolean;
  inputBytes: number;
  sha256: string;
  apkCount: number;
  packageName: string | null;
  classifications: string[];
  warnings: string[];
  unsupported: string[];
  failures: string[];
  signing: SigningResult[];
};

const DEFAULT_LOCAL_CORPUS = [
  "/Users/ahmadjalil/Downloads/iHunter+BC_5.0.69_APKPure.xapk"
];

const args = process.argv.slice(2);
const reportIndex = args.indexOf("--report");
const reportPath = reportIndex >= 0 ? args[reportIndex + 1] : undefined;
const manifestIndex = args.indexOf("--manifest");
const manifestPath = manifestIndex >= 0 ? args[manifestIndex + 1] : undefined;
const signingArg = args.find((arg) => arg.startsWith("--signing="));
const signingMode = parseSigningMode(signingArg?.slice("--signing=".length));
const optionValueIndexes = new Set<number>();
if (reportIndex >= 0) {
  optionValueIndexes.add(reportIndex);
  optionValueIndexes.add(reportIndex + 1);
}
if (manifestIndex >= 0) {
  optionValueIndexes.add(manifestIndex);
  optionValueIndexes.add(manifestIndex + 1);
}
const inputs = args.filter((arg, index) => !optionValueIndexes.has(index) && !arg.startsWith("--signing="));
const manifestCandidates = manifestPath ? await readManifest(manifestPath) : [];
const candidates = inputs.length > 0 || manifestCandidates.length > 0
  ? await expandInputs([...inputs, ...manifestCandidates])
  : await existingDefaultCorpus();
const results: CorpusResult[] = [];

for (const path of candidates) {
  results.push(await verifyOne(path));
}

for (const result of results) {
  console.log(`${result.ok ? "PASS" : "FAIL"} ${result.path}`);
  console.log(
    JSON.stringify(
      {
        inputBytes: result.inputBytes,
        sha256: result.sha256,
        apkCount: result.apkCount,
        packageName: result.packageName,
        classifications: result.classifications,
        warnings: result.warnings,
        unsupported: result.unsupported,
        failures: result.failures,
        signing: result.signing
      },
      null,
      2
    )
  );
}

const failed = results.filter((result) => !result.ok);
console.log(`Corpus summary: ${results.length - failed.length}/${results.length} passed.`);
if (reportPath) {
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, renderMarkdownReport(results));
  console.log(`Wrote ${reportPath}`);
  const jsonPath = reportPath.replace(/\.md$/i, ".json");
  await writeFile(jsonPath, `${JSON.stringify(renderJsonReport(results), null, 2)}\n`);
  console.log(`Wrote ${jsonPath}`);
}
if (failed.length > 0) {
  process.exitCode = 1;
}

async function existingDefaultCorpus(): Promise<string[]> {
  const existing: string[] = [];
  for (const path of DEFAULT_LOCAL_CORPUS) {
    try {
      await stat(path);
      existing.push(path);
    } catch {
      // This local sample is not available on the current machine.
    }
  }
  if (existing.length === 0) {
    throw new Error("No default local corpus samples were found. Pass one or more sample paths to verify:corpus.");
  }
  return existing;
}

async function expandInputs(paths: string[]): Promise<string[]> {
  const result: string[] = [];
  for (const path of paths) {
    const info = await stat(path);
    if (info.isDirectory()) {
      result.push(...await collectSamples(path));
    } else {
      result.push(path);
    }
  }
  return [...new Set(result)].sort();
}

async function readManifest(path: string): Promise<string[]> {
  const text = await readFile(path, "utf8");
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

async function collectSamples(directory: string): Promise<string[]> {
  const result: string[] = [];
  const names = await readdir(directory);
  for (const name of names) {
    const path = join(directory, name);
    const info = await stat(path);
    if (info.isDirectory()) {
      result.push(...await collectSamples(path));
    } else if (/\.(?:xapk|apks|apkm|zip|apk)$/i.test(name)) {
      result.push(path);
    }
  }
  return result;
}

async function verifyOne(path: string): Promise<CorpusResult> {
  const warnings: string[] = [];
  const unsupported: string[] = [];
  const failures: string[] = [];
  try {
    const bytes = await readFile(path);
    const inputBytes = new Uint8Array(bytes);
    const input = [{ name: basename(path), bytes: inputBytes }];
    const inspect = inspectPackage(input);
    const signing = [];
    if (inspect.apkEntries.length === 0) {
      failures.push("No APK entries were discovered.");
    }
    for (const mode of signingModesToRun(signingMode)) {
      const signingResult = await verifySigningMode(path, input, inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name), mode);
      signing.push(signingResult);
      warnings.push(...signingResult.warnings);
      unsupported.push(...signingResult.unsupported);
      failures.push(...signingResult.failures.map((failure) => `${mode}: ${failure}`));
    }
    const classifications = classifyMessages([...warnings, ...unsupported, ...failures]);

    return {
      path,
      ok: failures.length === 0,
      inputBytes: inputBytes.byteLength,
      sha256: sha256(inputBytes),
      apkCount: inspect.apkEntries.length,
      packageName: inspect.packageName,
      classifications,
      warnings,
      unsupported,
      failures,
      signing
    };
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
    return {
      path,
      ok: false,
      inputBytes: 0,
      sha256: "",
      apkCount: 0,
      packageName: null,
      classifications: classifyMessages(failures),
      warnings,
      unsupported,
      failures,
      signing: []
    };
  }
}

async function verifySigningMode(
  path: string,
  input: Array<{ name: string; bytes: Uint8Array }>,
  includeSplits: string[],
  mode: "v1" | "v1-v2" | "v1-v2-v3" | "v1-v2-v3-v4"
): Promise<SigningResult> {
  const warnings: string[] = [];
  const unsupported: string[] = [];
  const failures: string[] = [];
  const started = performance.now();
  const options: MergeOptions = {
    includeSplits,
    compressionLevel: 6,
    signingMode: mode
  };
  const result = mergePackage(input, options);
  const elapsedMs = Math.round(performance.now() - started);
  const entries = readCentralDirectory(result.apkBytes);
  const entryNames = new Set(entries.map((entry) => entry.name));
  const apkVerification = verifyMergedApk(result.apkBytes);
  const signingBlock = inspectApkSigningBlock(result.apkBytes);
  warnings.push(...result.warnings, ...apkVerification.warnings);
  unsupported.push(...result.unsupported);

  if (!entryNames.has("AndroidManifest.xml")) failures.push("Merged APK is missing AndroidManifest.xml.");
  if (!entries.some((entry) => /^classes\d*\.dex$/.test(entry.name))) failures.push("Merged APK is missing classes*.dex.");
  if (!entryNames.has("META-INF/ANTISPLT.RSA")) failures.push("Merged APK is missing generated JAR/v1 signature block.");
  if (apkVerification.warnings.length > 0) failures.push("APK structural verifier reported warnings.");
  if (result.unsupported.length > 0) failures.push("Merge reported unsupported scope.");
  if (mode === "v1" && signingBlock.present) {
    failures.push(`JAR/v1 output unexpectedly contains APK Signing Block pair(s): ${formatSigningBlockPairs(signingBlock)}.`);
  }
  if (mode === "v1-v2" && !hasOnlyWebV2Pair(signingBlock)) {
    failures.push(`v1-v2 output should contain exactly one fresh v2 pair, got: ${formatSigningBlockPairs(signingBlock)}.`);
  }
  if ((mode === "v1-v2-v3" || mode === "v1-v2-v3-v4") && !hasOnlyWebV2V3Pairs(signingBlock)) {
    failures.push(`${mode} output should contain exactly one fresh v2 pair and one fresh v3 pair, got: ${formatSigningBlockPairs(signingBlock)}.`);
  }
  if (mode === "v1-v2-v3-v4" && (!result.v4SidecarBytes || result.v4SidecarBytes.byteLength === 0)) {
    failures.push("v1-v2-v3-v4 output is missing the v4 sidecar.");
  }

  const javaApkSigPath = join("dist-fixtures", `corpus-${safeName(path)}-${mode}.apk`);
  await mkdir(dirname(javaApkSigPath), { recursive: true });
  await writeFile(javaApkSigPath, result.apkBytes);
  const javaIdsigPath = `${javaApkSigPath}.idsig`;
  if (result.v4SidecarBytes) {
    await writeFile(javaIdsigPath, result.v4SidecarBytes);
  }
  const javaApkSig = mode === "v1-v2-v3-v4"
    ? await verifyWithBundledApkSig(javaApkSigPath, 30, 35, javaIdsigPath)
    : mode === "v1-v2-v3"
    ? await verifyWithBundledApkSig(javaApkSigPath, 28, 35)
    : mode === "v1-v2"
    ? await verifyWithBundledApkSig(javaApkSigPath, 24, 27)
    : await verifyWithBundledApkSig(javaApkSigPath, 19, 23);
  const javaOk = mode === "v1-v2-v3-v4"
    ? javaApkSig.ok && javaApkSig.verifiedUsingV4 === true
    : mode === "v1-v2-v3"
    ? javaApkSig.ok && javaApkSig.verifiedUsingV3 === true
    : mode === "v1-v2"
    ? javaApkSig.ok && javaApkSig.verifiedUsingV2 === true
    : javaApkSig.ok && javaApkSig.verifiedUsingV1 === true;
  if (!javaOk) {
    failures.push(`Bundled Java apksig did not verify ${mode === "v1-v2-v3-v4" ? "v4 sidecar for Android 11.0+" : mode === "v1-v2-v3" ? "v3 for Android 9.0+" : mode === "v1-v2" ? "v2 for Android 7.0-8.1" : "v1 for Android 4.4-6.0"}.`);
  }
  const apkSigner = mode === "v1-v2" || mode === "v1-v2-v3" ? await verifyWithApkSigner(javaApkSigPath) : null;
  if (apkSigner && !apkSigner.ok) {
    failures.push(`Android SDK apksigner did not verify ${mode}.`);
  }
  const classifications = classifyMessages([...warnings, ...unsupported, ...failures]);

  return {
    mode,
    ok: failures.length === 0,
    outputBytes: result.apkBytes.byteLength,
    elapsedMs,
    signingBlock: result.v4SidecarBytes
      ? `${signingBlock.present ? signingBlock.pairs.map((pair) => pair.name).join(", ") || "present" : "none"} + v4 sidecar`
      : signingBlock.present ? signingBlock.pairs.map((pair) => pair.name).join(", ") || "present" : "none",
    javaApkSig: javaApkSig.available
      ? `${javaApkSig.ok ? "ok" : "fail"}${javaApkSig.verifiedUsingV1 ? " v1" : ""}${javaApkSig.verifiedUsingV2 ? " v2" : ""}${javaApkSig.verifiedUsingV3 ? " v3" : ""}${javaApkSig.verifiedUsingV4 ? " v4" : ""}`
      : `skipped: ${javaApkSig.skippedReason}`,
    apkSigner: apkSigner
      ? apkSigner.available
        ? `${apkSigner.ok ? "ok" : "fail"}${extractApkSignerSchemes(apkSigner.stdout)}`
        : `skipped: ${apkSigner.skippedReason}`
      : "not applicable",
    classifications,
    warnings,
    unsupported,
    failures
  };
}

function renderMarkdownReport(results: CorpusResult[]): string {
  const passed = results.filter((result) => result.ok).length;
  const generatedAt = new Date().toISOString();
  const rows = results.map((result) => {
    const status = result.ok ? "PASS" : "FAIL";
    const unsupported = result.unsupported.length > 0 ? result.unsupported.join("<br>") : "";
    const failures = result.failures.length > 0 ? result.failures.join("<br>") : "";
    const classifications = result.classifications.length > 0 ? result.classifications.join("<br>") : "";
    const signing = result.signing.map((item) => `${item.mode}: ${item.outputBytes ?? ""} bytes, ${item.signingBlock}, Java ${item.javaApkSig}, apksigner ${item.apkSigner}`).join("<br>");
    return `| ${status} | \`${result.path}\` | ${result.inputBytes} | \`${result.sha256}\` | ${escapeTable(result.packageName ?? "")} | ${result.apkCount} | ${escapeTable(signing)} | ${escapeTable(classifications)} | ${escapeTable(unsupported)} | ${escapeTable(failures)} |`;
  });

  return [
    "# AntiSplit Web Corpus Results",
    "",
    `Generated: ${generatedAt}`,
    "",
    `Summary: ${passed}/${results.length} passed.`,
    "",
    `Signing modes: ${signingModesToRun(signingMode).join(", ")}.`,
    "",
    "| Status | Path | Input bytes | SHA-256 | Package | APKs | Signing results | Classifications | Unsupported | Failures |",
    "| --- | --- | ---: | --- | --- | ---: | --- | --- | --- | --- |",
    ...rows,
    ""
  ].join("\n");
}

function classifyMessages(messages: string[]): string[] {
  const joined = messages.join("\n").toLowerCase();
  const classifications = new Set<string>();
  if (/resources?\.arsc|resource-table|type spec|type chunk|string pool|package identity|populated entr|arsc/.test(joined)) {
    classifications.add("resource-table");
  }
  if (/manifest|uses-split|split meta-data|requiredsplittypes|splittypes|binary xml/.test(joined)) {
    classifications.add("manifest");
  }
  if (/sign|signature|apksig|apksigner|v1|v2|v3|v4|jar\/v1|apk signing block|source stamp/.test(joined)) {
    classifications.add("signing");
  }
  if (/zip|central directory|compressed|alignment|aligned|eocd|native librar|structural verifier/.test(joined)) {
    classifications.add("zip-alignment");
  }
  if (/installed app|install intent|browser|platform-only|download/.test(joined)) {
    classifications.add("browser-platform");
  }
  if (messages.length > 0 && classifications.size === 0) {
    classifications.add("general");
  }
  return [...classifications].sort();
}

function renderJsonReport(results: CorpusResult[]) {
  const generatedAt = new Date().toISOString();
  const passed = results.filter((result) => result.ok).length;
  return {
    generatedAt,
    summary: {
      passed,
      total: results.length
    },
    signingModes: signingModesToRun(signingMode),
    results
  };
}

function parseSigningMode(value?: string): SigningMode {
  if (value === undefined) return "both";
  if (value === "v1" || value === "v2" || value === "v3" || value === "v4" || value === "both" || value === "all") return value;
  throw new Error(`Unsupported --signing value: ${value}. Expected v1, v2, v3, v4, both, or all.`);
}

function signingModesToRun(mode: SigningMode): Array<"v1" | "v1-v2" | "v1-v2-v3" | "v1-v2-v3-v4"> {
  if (mode === "v1") return ["v1"];
  if (mode === "v2") return ["v1-v2"];
  if (mode === "v3") return ["v1-v2-v3"];
  if (mode === "v4") return ["v1-v2-v3-v4"];
  if (mode === "all") return ["v1", "v1-v2", "v1-v2-v3", "v1-v2-v3-v4"];
  return ["v1", "v1-v2"];
}

function hasOnlyWebV2Pair(signingBlock: ReturnType<typeof inspectApkSigningBlock>): boolean {
  return signingBlock.present && signingBlock.pairs.length === 1 && signingBlock.pairs[0]?.idHex === "0x7109871a";
}

function hasOnlyWebV2V3Pairs(signingBlock: ReturnType<typeof inspectApkSigningBlock>): boolean {
  const ids = signingBlock.pairs.map((pair) => pair.idHex).sort();
  return signingBlock.present && ids.length === 2 && ids[0] === "0x7109871a" && ids[1] === "0xf05368c0";
}

function formatSigningBlockPairs(signingBlock: ReturnType<typeof inspectApkSigningBlock>): string {
  if (!signingBlock.present) {
    return "none";
  }
  return signingBlock.pairs.map((pair) => `${pair.name} (${pair.idHex})`).join(", ") || "present with no parsed pairs";
}

function extractApkSignerSchemes(stdout: string): string {
  const schemes = [
    ["v1", /Verified using v1 scheme .*: true/],
    ["v2", /Verified using v2 scheme .*: true/],
    ["v3", /Verified using v3 scheme .*: true/],
    ["v3.1", /Verified using v3\.1 scheme .*: true/],
    ["v4", /Verified using v4 scheme .*: true/]
  ] as const;
  const verified = schemes.filter(([, pattern]) => pattern.test(stdout)).map(([scheme]) => scheme);
  return verified.length > 0 ? ` ${verified.join(" ")}` : "";
}

function safeName(path: string): string {
  return basename(path).replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/\.(xapk|apks|apkm|zip|apk)$/i, "");
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

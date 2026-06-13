import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { spawnFile } from "./process";
import { unzipSync } from "fflate";
import { analyzeResourceTable, summarizeArsc } from "../src/arscAnalyzer";
import { inspectApkSigningBlock, readCentralDirectory, verifyMergedApk } from "../src/apkVerification";
import { verifyV2Signature } from "../src/apkV2Verifier";
import { inspectPackage, mergePackage } from "../src/mergeCore";

type ApkSummary = {
  path: string;
  bytes: number;
  entryCount: number;
  verificationWarnings: string[];
  signingBlock: string;
  v2Verified: boolean;
  v2Warnings: string[];
  resources?: string;
  manifestBytes?: number;
  resourceBytes?: number;
};

type JavaWebReport = {
  fixturePath: string;
  java: ApkSummary;
  webUnsigned: ApkSummary;
  webV2: ApkSummary;
  unsignedComparison: Awaited<ReturnType<typeof compareEntrySets>>;
  findings: string[];
};

const fixturePath = process.argv[2] ?? "/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk";
const outputDir = "dist-fixtures";
const sampleSlug = safeName(fixturePath);
const javaOutputPath = join(outputDir, `${sampleSlug}_java_antisplit_unsigned.apk`);
const webUnsignedOutputPath = join(outputDir, `${sampleSlug}_web_antisplit_unsigned.apk`);
const webV2OutputPath = join(outputDir, `${sampleSlug}_web_antisplit_v2.apk`);
const javaHome = await findJavaHome();

await mkdir(outputDir, { recursive: true });
await compileJavaRunner(javaHome);
await runJavaRunner(javaHome, fixturePath, javaOutputPath);
await writeWebOutputs(fixturePath, webUnsignedOutputPath, webV2OutputPath);

const javaSummary = await summarizeApk(javaOutputPath);
const webUnsignedSummary = await summarizeApk(webUnsignedOutputPath);
const webV2Summary = await summarizeApk(webV2OutputPath);
const entryDiff = await compareEntrySets(javaOutputPath, webUnsignedOutputPath);

const report: JavaWebReport = {
  fixturePath,
  java: javaSummary,
  webUnsigned: webUnsignedSummary,
  webV2: webV2Summary,
  unsignedComparison: entryDiff,
  findings: [
    javaSummary.v2Verified
      ? "Java output contains a v2 block that verifies."
      : "Java output contains a carried APK Signing Block, but its v2 digest does not verify after merging.",
    webUnsignedSummary.v2Verified
      ? "Web unsigned output unexpectedly contains a valid v2 block."
      : "Web unsigned output strips stale signing material and has no v2 block.",
    webV2Summary.v2Verified
      ? "Web v2 output contains a browser-generated v2 block that verifies with the local verifier."
      : "Web v2 output did not verify with the local verifier."
  ]
};

const markdownPath = join("docs", `java-web-comparison-${sampleSlug}.md`);
const jsonPath = join("docs", `java-web-comparison-${sampleSlug}.json`);
await mkdir("docs", { recursive: true });
await writeFile(markdownPath, renderMarkdown(report));
await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
if (sampleSlug === "REON_POCKET_2.2.0_APKPure") {
  await writeFile("docs/java-web-comparison.md", renderMarkdown(report));
  await writeFile("docs/java-web-comparison.json", `${JSON.stringify(report, null, 2)}\n`);
}

console.log(JSON.stringify(report, null, 2));
console.log(`Wrote ${markdownPath}`);
console.log(`Wrote ${jsonPath}`);

async function findJavaHome(): Promise<string> {
  const candidates = [
    process.env.JAVA_HOME,
    "/opt/homebrew/opt/openjdk",
    "/opt/homebrew/opt/openjdk@17",
    "/usr/local/opt/openjdk",
    "/usr/local/opt/openjdk@17"
  ].filter((value): value is string => Boolean(value));

  for (const candidate of candidates) {
    try {
      await access(join(candidate, "bin", "java"));
      await access(join(candidate, "bin", "javac"));
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }
  throw new Error("Could not find a JDK. Install OpenJDK or set JAVA_HOME to a JDK with java and javac.");
}

async function compileJavaRunner(javaHome: string): Promise<void> {
  await mkdir("build/java-tools/classes", { recursive: true });
  await spawnFile(join(javaHome, "bin", "javac"), [
    "-encoding",
    "UTF-8",
    "-source",
    "8",
    "-target",
    "8",
    "-cp",
    "tools/java:app/src/main/java",
    "-sourcepath",
    "tools/java:app/src/main/java",
    "-d",
    "build/java-tools/classes",
    "tools/java/CompareJavaMerge.java"
  ]);
}

async function runJavaRunner(javaHome: string, inputPath: string, outputPath: string): Promise<void> {
  await spawnFile(join(javaHome, "bin", "java"), [
    "-cp",
    "build/java-tools/classes",
    "CompareJavaMerge",
    inputPath,
    outputPath
  ]);
}

async function writeWebOutputs(inputPath: string, unsignedPath: string, v2Path: string): Promise<void> {
  const bytes = await readFile(inputPath);
  const input = [{ name: basename(inputPath), bytes: new Uint8Array(bytes) }];
  const inspect = inspectPackage(input);
  const includeSplits = inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name);
  const unsigned = mergePackage(input, { includeSplits, compressionLevel: 6, signingMode: "none" });
  const v2 = mergePackage(input, { includeSplits, compressionLevel: 6, signingMode: "v1-v2" });
  await writeFile(unsignedPath, unsigned.apkBytes);
  await writeFile(v2Path, v2.apkBytes);
}

async function summarizeApk(path: string): Promise<ApkSummary> {
  const bytes = new Uint8Array(await readFile(path));
  const entries = readCentralDirectory(bytes);
  const verification = verifyMergedApk(bytes);
  const signingBlock = inspectApkSigningBlock(bytes);
  const v2 = verifyV2Signature(bytes);
  const zip = unzipSync(bytes, {
    filter: (entry) => entry.name === "AndroidManifest.xml" || entry.name === "resources.arsc"
  });
  const resourceBytes = zip["resources.arsc"];
  const manifestBytes = zip["AndroidManifest.xml"];
  const resources = resourceBytes ? summarizeArsc(analyzeResourceTable(resourceBytes)) : undefined;

  return {
    path,
    bytes: bytes.byteLength,
    entryCount: entries.length,
    verificationWarnings: verification.warnings,
    signingBlock: signingBlock.present ? signingBlock.pairs.map((pair) => pair.name).join(", ") || "present" : "none",
    v2Verified: v2.verified,
    v2Warnings: v2.warnings,
    resources,
    manifestBytes: manifestBytes?.byteLength,
    resourceBytes: resourceBytes?.byteLength
  };
}

async function compareEntrySets(leftPath: string, rightPath: string) {
  const leftBytes = new Uint8Array(await readFile(leftPath));
  const rightBytes = new Uint8Array(await readFile(rightPath));
  const left = new Map(readCentralDirectory(leftBytes).map((entry) => [entry.name, entry]));
  const right = new Map(readCentralDirectory(rightBytes).map((entry) => [entry.name, entry]));
  const common = [...left.keys()].filter((name) => right.has(name));
  const onlyLeft = [...left.keys()].filter((name) => !right.has(name)).sort();
  const onlyRight = [...right.keys()].filter((name) => !left.has(name)).sort();
  const differentUncompressedSize = common
    .filter((name) => left.get(name)?.uncompressedSize !== right.get(name)?.uncompressedSize)
    .sort()
    .map((name) => ({
      name,
      java: left.get(name)?.uncompressedSize,
      web: right.get(name)?.uncompressedSize
    }));

  return {
    onlyJavaCount: onlyLeft.length,
    onlyWebCount: onlyRight.length,
    onlyJava: onlyLeft,
    onlyWeb: onlyRight,
    differentUncompressedSizeCount: differentUncompressedSize.length,
    differentUncompressedSize
  };
}

function renderMarkdown(report: JavaWebReport): string {
  return [
    "# Java vs Web Comparison",
    "",
    `Fixture: \`${report.fixturePath}\``,
    "",
    "| Output | Bytes | Entries | Signing block | v2 verifies | Resource summary | Warnings |",
    "| --- | ---: | ---: | --- | --- | --- | --- |",
    renderRow("Java/REAndroid unsigned", report.java),
    renderRow("Web unsigned", report.webUnsigned),
    renderRow("Web v1+v2", report.webV2),
    "",
    "## Entry Differences",
    "",
    `Only Java: ${report.unsignedComparison.onlyJavaCount}`,
    "",
    ...report.unsignedComparison.onlyJava.map((name) => `- \`${name}\``),
    "",
    `Only web: ${report.unsignedComparison.onlyWebCount}`,
    "",
    ...report.unsignedComparison.onlyWeb.map((name) => `- \`${name}\``),
    "",
    "Different uncompressed sizes:",
    "",
    ...report.unsignedComparison.differentUncompressedSize.map((entry) => `- \`${entry.name}\`: Java ${entry.java}, web ${entry.web}`),
    "",
    "## Findings",
    "",
    ...report.findings.map((finding) => `- ${finding}`),
    ""
  ].join("\n");
}

function renderRow(label: string, summary: ApkSummary): string {
  return [
    label,
    String(summary.bytes),
    String(summary.entryCount),
    escapeTable(summary.signingBlock),
    summary.v2Verified ? "yes" : "no",
    escapeTable(summary.resources ?? ""),
    escapeTable([...summary.verificationWarnings, ...summary.v2Warnings].join("<br>"))
  ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

function safeName(path: string): string {
  return basename(path).replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/\.(xapk|apks|apkm|zip|apk)$/i, "");
}

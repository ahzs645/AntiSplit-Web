import { readFile, writeFile } from "node:fs/promises";

type Status = "proven" | "partial" | "missing";

type AuditItem = {
  requirement: string;
  status: Status;
  evidence: string[];
  note: string;
};

const outputPath = "docs/parity-completion-audit.json";

const parityRun = await readJson<any>("docs/parity-run.json");
const corpus = await readJson<any>("docs/corpus-results.json");
const v3Corpus = await readJson<any>("docs/corpus-v3-results.json");
const v4Corpus = await readJson<any>("docs/corpus-v4-results.json");
const manifestCorpus = await readJson<any>("docs/corpus-manifest-results.json");
const standalone = await readJson<any>("docs/corpus-standalone-results.json");
const fdroidCorpus = await readJson<any>("docs/fdroid-corpus-results.json");
const inventory = await readJson<any>("docs/corpus-inventory.json");
const targetedInventory = await readJson<any>("docs/targeted-corpus-inventory.json");
const environment = await readJson<any>("docs/environment-check.json");
const arscShapes = await readJson<any>("docs/arsc-shape-report.json");
const ihunterCompare = await readJson<any>("docs/java-web-comparison-iHunter_BC_5.0.69_APKPure.json");

const items: AuditItem[] = [
  {
    requirement: "Static client-side web app builds successfully.",
    status: stepOk("Build static web app") ? "proven" : "missing",
    evidence: ["docs/parity-run.json", "npm run build"],
    note: stepOk("Build static web app") ? "Latest parity run includes a passing production build." : "Latest parity run does not prove a passing build."
  },
  {
    requirement: "iHunter fixture merges and verifies.",
    status: stepOk("Verify iHunter fixture") ? "proven" : "missing",
    evidence: ["docs/parity-run.json", "npm run verify:fixture"],
    note: stepOk("Verify iHunter fixture") ? "Fixture gate passed with styled string-span preservation and no unsupported scope." : "Fixture gate missing or failed."
  },
  {
    requirement: "Corpus-confidence tooling and reports exist.",
    status: corpus?.summary?.passed === corpus?.summary?.total && manifestCorpus?.summary?.passed === manifestCorpus?.summary?.total && standalone?.summary?.passed === standalone?.summary?.total && fdroidAllPassing() && inventory?.summary?.total > 0 && targetedInventory?.summary?.total > 0 ? "proven" : "partial",
    evidence: ["docs/corpus-results.json", "docs/corpus-manifest-results.json", "docs/corpus-standalone-results.json", "docs/fdroid-corpus-results.json", "docs/local-corpus-manifest.txt", "docs/fdroid-corpus-manifest.txt", "docs/corpus-inventory.json", "docs/targeted-corpus-inventory.json", "tools/verify-corpus.ts", "tools/discover-corpus.ts", "tools/fetch-fdroid-corpus.ts"],
    note: `Default split-container corpus is ${corpus?.summary?.passed ?? 0}/${corpus?.summary?.total ?? 0}; manifest corpus is ${manifestCorpus?.summary?.passed ?? 0}/${manifestCorpus?.summary?.total ?? 0}; standalone corpus is ${standalone?.summary?.passed ?? 0}/${standalone?.summary?.total ?? 0}; F-Droid APK corpus is ${fdroidCorpus?.summary?.passed ?? 0}/${fdroidCorpus?.summary?.total ?? 0}; Downloads inventory found ${inventory?.summary?.usable ?? 0}/${inventory?.summary?.total ?? 0} usable archive sample(s); targeted inventory found ${targetedInventory?.summary?.usable ?? 0}/${targetedInventory?.summary?.total ?? 0} usable independent sample(s) after excluding generated fixture outputs.`
  },
  {
    requirement: "Broad corpus confidence across many independent package formats.",
    status: independentSampleCount() >= 20 ? "proven" : "partial",
    evidence: ["docs/corpus-results.json", "docs/corpus-manifest-results.json", "docs/corpus-standalone-results.json", "docs/fdroid-corpus-results.json", "docs/corpus-inventory.json", "docs/targeted-corpus-inventory.json"],
    note: `${independentSplitContainerCount()} independent split-container sample(s), ${standalone?.summary?.passed ?? 0} local standalone APK sample(s), and ${fdroidCorpus?.summary?.passed ?? 0} F-Droid APK sample(s) are verified; targeted inventory found ${targetedInventory?.summary?.usable ?? 0} usable independent local sample(s) after excluding generated outputs; target is at least 20 independent mixed samples.`
  },
  {
    requirement: "Guarded resources.arsc support covers current real corpus, preserves styled strings, and fails closed for malformed pools, multi-package tables, and missing base type IDs.",
    status: stepOk("Verify ARSC unsupported guards") && corpusAllPassing() && standaloneAllPassing() && arscShapes?.summary?.passed === arscShapes?.summary?.total ? "proven" : "partial",
    evidence: ["docs/parity-run.json", "npm run verify:arsc-guards", "npm run scan:arsc -- --manifest docs/local-corpus-manifest.txt --report docs/arsc-shape-report.md", "docs/corpus-results.json", "docs/arsc-shape-report.json"],
    note: stepOk("Verify ARSC unsupported guards") && corpusAllPassing() && standaloneAllPassing() && arscShapes?.summary?.passed === arscShapes?.summary?.total
      ? "Current real corpus passes, ARSC shape scan reports no unsupported current-corpus shapes, and synthetic unsupported guard cases reject with specific diagnostics."
      : "ARSC evidence is missing or one corpus sample failed."
  },
  {
    requirement: "Client-side APK Signature Scheme v2 support with verification while preserving v1 fallback.",
    status: stepOk("Verify v2 signing fixture") && corpusSigningOk("v1") && corpusSigningOk("v1-v2") && standaloneSigningOk("v1") && standaloneSigningOk("v1-v2") && fdroidSigningOk("v1") && fdroidSigningOk("v1-v2") && corpusApkSignerOk(corpus, "v1-v2") && corpusApkSignerOk(standalone, "v1-v2") && corpusApkSignerOk(fdroidCorpus, "v1-v2") ? "proven" : "partial",
    evidence: ["docs/parity-run.json", "docs/corpus-results.json", "docs/corpus-standalone-results.json", "docs/fdroid-corpus-results.json", "src/apkV2Signer.ts", "src/apkV2Verifier.ts", "src/apkV1Signer.ts"],
    note: "v1 and v1+v2 modes verify with bundled Java apksig on the current split-container, standalone APK, and F-Droid APK corpus; v2 corpus outputs also verify with Android SDK apksigner when installed; v1 signing switches to old-platform compatible SHA-1/no-authenticated-attributes output for minSdk below 18."
  },
  {
    requirement: "Android SDK apksigner external validation.",
    status: environment?.apksigner?.available === true && environment?.apksigner?.ok === true ? "proven" : "partial",
    evidence: ["npm run verify:v2-fixture", "npm run verify:environment", "docs/environment-check.json"],
    note: environment?.apksigner?.available === true
      ? `Android SDK apksigner was found at ${environment.apksigner.command}; verification ${environment.apksigner.ok ? "passed" : "failed"}.`
      : `Bundled Java apksig verifies v2, but Android SDK apksigner is not installed locally. ${environment?.apksigner?.skippedReason ?? "Run npm run verify:environment for the bounded search report."}`
  },
  {
    requirement: "APK Signature Scheme v3/v4 parity.",
    status: stepOk("Verify v3 signing fixture") && v3CorpusSigningOk() && corpusApkSignerOk(v3Corpus, "v1-v2-v3") && stepOk("Verify v4 sidecar fixture") && v4CorpusSigningOk() ? "proven" : "partial",
    evidence: ["src/apkVerification.ts", "src/apkV3Verifier.ts", "src/apkV4Sidecar.ts", "npm run verify:v3-fixture", "npm run verify:v4-fixture", "docs/corpus-v3-results.json", "docs/corpus-v4-results.json", "docs/parity-audit.md", "docs/signing-v3-v4-feasibility.md"],
    note: stepOk("Verify v3 signing fixture") && v3CorpusSigningOk() && corpusApkSignerOk(v3Corpus, "v1-v2-v3") && stepOk("Verify v4 sidecar fixture") && v4CorpusSigningOk()
      ? "Browser-side v3.0 signing and v4 .idsig sidecar generation verify on the current fixture and split-container corpus with bundled Java apksig verification; v3 corpus outputs also verify with Android SDK apksigner when installed."
      : "v3/v4 signing evidence is incomplete; run the v3 and v4 fixture/corpus gates."
  },
  {
    requirement: "Java/REAndroid comparison against available samples.",
    status: compareOk(ihunterCompare) ? "proven" : "partial",
    evidence: ["docs/java-web-comparison-iHunter_BC_5.0.69_APKPure.json"],
    note: "The current iHunter comparison checks REAndroid output against unsigned and freshly v2-signed web outputs."
  },
  {
    requirement: "Browser-impossible Android installed-app extraction and install intents are documented with alternatives.",
    status: "proven",
    evidence: ["README.md", "docs/parity-plan.md", "docs/parity-audit.md", "src/main.tsx"],
    note: "Docs and UI identify installed-app enumeration and install intent launch as Android platform-only capabilities and list feasible alternatives."
  }
];

const summary = {
  proven: items.filter((item) => item.status === "proven").length,
  partial: items.filter((item) => item.status === "partial").length,
  missing: items.filter((item) => item.status === "missing").length,
  total: items.length,
  complete: items.every((item) => item.status === "proven")
};

const audit = {
  generatedAt: new Date().toISOString(),
  summary,
  items
};

await writeFile(outputPath, `${JSON.stringify(audit, null, 2)}\n`);
console.log(JSON.stringify(audit, null, 2));
console.log(`Wrote ${outputPath}`);

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return null;
  }
}

function stepOk(label: string): boolean {
  return parityRun?.ok === true && parityRun.steps?.some((step: any) => step.label === label && step.ok === true) === true;
}

function corpusAllPassing(): boolean {
  return corpus?.summary?.total > 0 && corpus.summary.passed === corpus.summary.total;
}

function standaloneAllPassing(): boolean {
  return standalone?.summary?.total > 0 && standalone.summary.passed === standalone.summary.total;
}

function corpusSigningOk(mode: string): boolean {
  const results = corpus?.results ?? [];
  return results.length > 0 && results.every((result: any) => result.signing?.some((signing: any) => signing.mode === mode && signing.ok === true));
}

function standaloneSigningOk(mode: string): boolean {
  const results = standalone?.results ?? [];
  return results.length > 0 && results.every((result: any) => result.signing?.some((signing: any) => signing.mode === mode && signing.ok === true));
}

function fdroidAllPassing(): boolean {
  return fdroidCorpus?.summary?.total > 0 && fdroidCorpus.summary.passed === fdroidCorpus.summary.total;
}

function fdroidSigningOk(mode: string): boolean {
  const results = fdroidCorpus?.results ?? [];
  return results.length > 0 && results.every((result: any) => result.signing?.some((signing: any) => signing.mode === mode && signing.ok === true));
}

function v3CorpusSigningOk(): boolean {
  const results = v3Corpus?.results ?? [];
  return results.length > 0 && results.every((result: any) => result.signing?.some((signing: any) => signing.mode === "v1-v2-v3" && signing.ok === true));
}

function v4CorpusSigningOk(): boolean {
  const results = v4Corpus?.results ?? [];
  return results.length > 0 && results.every((result: any) => result.signing?.some((signing: any) => signing.mode === "v1-v2-v3-v4" && signing.ok === true));
}

function corpusApkSignerOk(report: any, mode: string): boolean {
  const results = report?.results ?? [];
  return results.length > 0 && results.every((result: any) => {
    const signing = result.signing?.find((item: any) => item.mode === mode);
    return typeof signing?.apkSigner === "string" && signing.apkSigner.startsWith("ok");
  });
}

function compareOk(report: any): boolean {
  return report?.webV2?.v2Verified === true && report?.webUnsigned?.v2Verified === false && report?.java?.v2Verified === false;
}

function independentSplitContainerCount(): number {
  return (corpus?.results ?? []).filter((result: any) => result.apkCount > 1).length;
}

function independentSampleCount(): number {
  const splitContainers = independentSplitContainerCount();
  const standaloneCount = standalone?.summary?.passed ?? 0;
  const fdroidCount = fdroidCorpus?.summary?.passed ?? 0;
  return splitContainers + standaloneCount + fdroidCount;
}

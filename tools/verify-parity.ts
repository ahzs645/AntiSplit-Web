import { spawnFile } from "./process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

type Step = {
  label: string;
  command: string;
  args: string[];
};

const SUMMARY_PATH = "docs/parity-run.json";

const coreSteps: Step[] = [
  { label: "Build static web app", command: "npm", args: ["run", "build"] },
  { label: "Verify iHunter fixture", command: "npm", args: ["run", "verify:fixture"] },
  { label: "Verify v2 signing fixture", command: "npm", args: ["run", "verify:v2-fixture"] },
  { label: "Verify v3 signing fixture", command: "npm", args: ["run", "verify:v3-fixture"] },
  { label: "Verify v4 sidecar fixture", command: "npm", args: ["run", "verify:v4-fixture"] },
  { label: "Verify ARSC unsupported guards", command: "npm", args: ["run", "verify:arsc-guards"] },
  { label: "Discover targeted corpus inventory", command: "npm", args: ["run", "discover:corpus", "--", "/Users/ahmadjalil/Downloads", "/Users/ahmadjalil/Desktop", "/Users/ahmadjalil/Documents", "/Users/ahmadjalil/github/AntiSplit-Web", "--report", "docs/targeted-corpus-inventory.md"] },
  { label: "Verify default corpus", command: "npm", args: ["run", "verify:corpus", "--", "--report", "docs/corpus-results.md"] },
  { label: "Verify v3 corpus", command: "npm", args: ["run", "verify:v3-corpus"] },
  { label: "Verify v4 corpus", command: "npm", args: ["run", "verify:v4-corpus"] },
  { label: "Verify manifest corpus", command: "npm", args: ["run", "verify:corpus", "--", "--manifest", "docs/local-corpus-manifest.txt", "--report", "docs/corpus-manifest-results.md"] },
  { label: "Fetch F-Droid APK corpus", command: "npm", args: ["run", "fetch:fdroid-corpus"] },
  { label: "Verify F-Droid APK corpus", command: "npm", args: ["run", "verify:fdroid-corpus"] },
  { label: "Scan ARSC shapes", command: "npm", args: ["run", "scan:arsc", "--", "--manifest", "docs/local-corpus-manifest.txt", "--report", "docs/arsc-shape-report.md"] },
  { label: "Verify local environment", command: "npm", args: ["run", "verify:environment"] },
  { label: "Compare Java vs web on iHunter", command: "npm", args: ["run", "compare:java-web"] }
];

const auditStep: Step = { label: "Audit completion evidence", command: "npm", args: ["run", "audit:parity"] };
const steps: Step[] = [...coreSteps, auditStep];
const startedAt = new Date();
const stepResults: Array<Step & { ok: boolean; elapsedMs: number; error?: string }> = [];

for (const [index, step] of coreSteps.entries()) {
  console.log(`\n[${index + 1}/${steps.length}] ${step.label}`);
  const started = performance.now();
  try {
    await spawnFile(step.command, step.args);
    stepResults.push({ ...step, ok: true, elapsedMs: Math.round(performance.now() - started) });
  } catch (error) {
    stepResults.push({
      ...step,
      ok: false,
      elapsedMs: Math.round(performance.now() - started),
      error: error instanceof Error ? error.message : String(error)
    });
    await writeSummary(startedAt, stepResults, coreSteps);
    throw error;
  }
}

// The completion audit reads docs/parity-run.json as evidence, so write the current
// successful core run before invoking the audit step.
await writeSummary(startedAt, stepResults, coreSteps);
const auditStarted = performance.now();
console.log(`\n[${steps.length}/${steps.length}] ${auditStep.label}`);
try {
  await spawnFile(auditStep.command, auditStep.args);
  stepResults.push({ ...auditStep, ok: true, elapsedMs: Math.round(performance.now() - auditStarted) });
} catch (error) {
  stepResults.push({
    ...auditStep,
    ok: false,
    elapsedMs: Math.round(performance.now() - auditStarted),
    error: error instanceof Error ? error.message : String(error)
  });
  await writeSummary(startedAt, stepResults, steps);
  throw error;
}

await writeSummary(startedAt, stepResults, steps);
console.log(`\nParity verification completed. Wrote ${SUMMARY_PATH}.`);

async function writeSummary(startedAt: Date, results: Array<Step & { ok: boolean; elapsedMs: number; error?: string }>, expectedSteps = steps): Promise<void> {
  const finishedAt = new Date();
  const summary = {
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    elapsedMs: finishedAt.getTime() - startedAt.getTime(),
    ok: results.every((result) => result.ok) && results.length === expectedSteps.length,
    completedSteps: results.length,
    totalSteps: expectedSteps.length,
    steps: results.map((result) => ({
      label: result.label,
      command: [result.command, ...result.args].join(" "),
      ok: result.ok,
      elapsedMs: result.elapsedMs,
      error: result.error
    }))
  };
  await mkdir(dirname(SUMMARY_PATH), { recursive: true });
  await writeFile(SUMMARY_PATH, `${JSON.stringify(summary, null, 2)}\n`);
}

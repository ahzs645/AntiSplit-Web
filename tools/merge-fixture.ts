import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { inspectPackage, mergePackage } from "../src/mergeCore";

const inputPath = process.argv[2];
if (!inputPath) {
  throw new Error("Usage: npm run merge:fixture -- /path/to/file.xapk [--no-sign|--v2]");
}
const flags = new Set(process.argv.slice(3));

const started = performance.now();
const bytes = await readFile(inputPath);
const input = [{ name: basename(inputPath), bytes: new Uint8Array(bytes) }];

const inspect = inspectPackage(input);
console.log("Inspect:");
console.log(JSON.stringify(inspect, null, 2));

const result = mergePackage(
  input,
  {
    includeSplits: inspect.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name),
    compressionLevel: 6,
    signingMode: flags.has("--no-sign") ? "none" : flags.has("--v2") ? "v1-v2" : "v1"
  },
  (message) => console.log(message)
);

await mkdir("dist-fixtures", { recursive: true });
const outputPath = join("dist-fixtures", result.fileName);
await writeFile(outputPath, result.apkBytes);

const elapsedMs = performance.now() - started;
console.log("Result:");
console.log(
  JSON.stringify(
    {
      outputPath,
      outputBytes: result.apkBytes.byteLength,
      elapsedMs: Math.round(elapsedMs),
      warnings: result.warnings,
      unsupported: result.unsupported,
      verification: result.verification,
      resourceDiagnostics: result.resourceDiagnostics
    },
    null,
    2
  )
);

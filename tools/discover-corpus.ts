import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { readCentralDirectory } from "../src/apkVerification";

type CandidateKind = "split-container" | "standalone-apk" | "generated-output-apk" | "split-component-apk" | "generic-zip" | "invalid-zip";

type InventoryItem = {
  path: string;
  kind: CandidateKind;
  usableCorpusSample: boolean;
  entryCount: number;
  apkEntryCount: number;
  apkEntries: string[];
  hasAndroidManifest: boolean;
  hasDex: boolean;
  reason: string;
};

const args = process.argv.slice(2);
const reportIndex = args.indexOf("--report");
const reportPath = reportIndex >= 0 ? args[reportIndex + 1] : undefined;
const includeIgnored = args.includes("--include-ignored");
const roots = args.filter((arg, index) => index !== reportIndex && index !== reportIndex + 1 && arg !== "--include-ignored");
const scanRoots = roots.length > 0 ? roots : ["/Users/ahmadjalil/Downloads"];
const DEFAULT_IGNORED_DIR_NAMES = new Set([
  ".cache",
  ".codex",
  ".git",
  ".npm",
  ".pnpm-store",
  ".Trash",
  "Library",
  "node_modules",
  "dist",
  "build",
  "target"
]);

const paths = (await Promise.all(scanRoots.map((root) => collectArchives(root)))).flat();
const items = await Promise.all([...new Set(paths)].sort().map((path) => inspectArchive(path)));
const usable = items.filter((item) => item.usableCorpusSample);

for (const item of items) {
  console.log(`${item.usableCorpusSample ? "USE" : "SKIP"} ${item.kind} ${item.path}`);
  console.log(`  ${item.reason}`);
}
console.log(`Corpus inventory: ${usable.length}/${items.length} usable archive sample(s).`);

if (reportPath) {
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, renderMarkdown(items));
  const jsonPath = reportPath.replace(/\.md$/i, ".json");
  await writeFile(jsonPath, `${JSON.stringify(renderJson(items), null, 2)}\n`);
  console.log(`Wrote ${reportPath}`);
  console.log(`Wrote ${jsonPath}`);
}

async function collectArchives(root: string): Promise<string[]> {
  const result: string[] = [];
  const info = await statOrNull(root);
  if (!info) {
    return result;
  }
  if (info.isFile()) {
    return isArchiveName(root) ? [root] : [];
  }
  let names: string[];
  try {
    names = await readdir(root);
  } catch {
    return result;
  }
  for (const name of names) {
    const path = join(root, name);
    const child = await statOrNull(path);
    if (!child) {
      continue;
    }
    if (child.isDirectory()) {
      if (!includeIgnored && DEFAULT_IGNORED_DIR_NAMES.has(name)) {
        continue;
      }
      result.push(...await collectArchives(path));
    } else if (isArchiveName(name)) {
      result.push(path);
    }
  }
  return result;
}

async function statOrNull(path: string): Promise<Awaited<ReturnType<typeof stat>> | null> {
  try {
    return await stat(path);
  } catch {
    return null;
  }
}

async function inspectArchive(path: string): Promise<InventoryItem> {
  try {
    const bytes = new Uint8Array(await readFile(path));
    const entries = readCentralDirectory(bytes);
    const names = entries.map((entry) => entry.name);
    const apkEntries = names.filter((name) => /\.apk$/i.test(name)).sort();
    const hasAndroidManifest = names.includes("AndroidManifest.xml");
    const hasDex = names.some((name) => /^classes\d*\.dex$/i.test(name));
    const extension = extensionOf(path);
    const kind = classify(path, extension, apkEntries.length, hasAndroidManifest, hasDex);
    const usableCorpusSample = kind === "split-container" || kind === "standalone-apk";
    return {
      path,
      kind,
      usableCorpusSample,
      entryCount: entries.length,
      apkEntryCount: apkEntries.length,
      apkEntries,
      hasAndroidManifest,
      hasDex,
      reason: reasonFor(kind, apkEntries.length, hasDex)
    };
  } catch (error) {
    return {
      path,
      kind: "invalid-zip",
      usableCorpusSample: false,
      entryCount: 0,
      apkEntryCount: 0,
      apkEntries: [],
      hasAndroidManifest: false,
      hasDex: false,
      reason: error instanceof Error ? error.message : String(error)
    };
  }
}

function classify(path: string, extension: string, apkEntryCount: number, hasAndroidManifest: boolean, hasDex: boolean): CandidateKind {
  if (isGeneratedOutput(path) && extension === ".apk" && hasAndroidManifest && hasDex) {
    return "generated-output-apk";
  }
  if ((extension === ".xapk" || extension === ".apks" || extension === ".apkm") && apkEntryCount > 0) {
    return "split-container";
  }
  if (extension === ".apk" && hasAndroidManifest && hasDex) {
    return "standalone-apk";
  }
  if (extension === ".apk" && hasAndroidManifest && !hasDex) {
    return "split-component-apk";
  }
  if (extension === ".zip" && apkEntryCount > 0) {
    return "split-container";
  }
  return "generic-zip";
}

function reasonFor(kind: CandidateKind, apkEntryCount: number, hasDex: boolean): string {
  switch (kind) {
    case "split-container":
      return `Archive contains ${apkEntryCount} APK entr${apkEntryCount === 1 ? "y" : "ies"} and can be passed to verify:corpus.`;
    case "standalone-apk":
      return "APK contains AndroidManifest.xml and classes*.dex and can be passed to verify:corpus.";
    case "generated-output-apk":
      return "APK is generated under this repository's fixture output directory; useful for debugging but not counted as an independent corpus sample.";
    case "split-component-apk":
      return "APK looks like a config/split component without classes*.dex; verify the parent container instead.";
    case "generic-zip":
      return hasDex ? "ZIP is not an APK container despite containing DEX-like entries." : "ZIP does not contain APK entries or an APK manifest/DEX layout.";
    case "invalid-zip":
      return "Archive could not be read as a ZIP/APK.";
  }
}

function renderMarkdown(items: InventoryItem[]): string {
  const usable = items.filter((item) => item.usableCorpusSample).length;
  const generatedAt = new Date().toISOString();
  return [
    "# Corpus Inventory",
    "",
    `Generated: ${generatedAt}`,
    "",
    `Summary: ${usable}/${items.length} usable archive sample(s).`,
    "",
    "| Use | Kind | Path | Entries | APK entries | Reason |",
    "| --- | --- | --- | ---: | ---: | --- |",
    ...items.map((item) => `| ${item.usableCorpusSample ? "yes" : "no"} | ${item.kind} | \`${item.path}\` | ${item.entryCount} | ${item.apkEntryCount} | ${escapeTable(item.reason)} |`),
    ""
  ].join("\n");
}

function renderJson(items: InventoryItem[]) {
  const usable = items.filter((item) => item.usableCorpusSample).length;
  return {
    generatedAt: new Date().toISOString(),
    summary: {
      usable,
      total: items.length
    },
    items
  };
}

function isArchiveName(path: string): boolean {
  return /\.(?:xapk|apks|apkm|zip|apk)$/i.test(path);
}

function extensionOf(path: string): string {
  const match = basename(path).match(/(\.[^.]+)$/);
  return match?.[1].toLowerCase() ?? "";
}

function isGeneratedOutput(path: string): boolean {
  return /\/dist-fixtures\//.test(path);
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

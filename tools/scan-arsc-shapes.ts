import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { unzipSync } from "fflate";

type ApkShape = {
  name: string;
  role: "base" | "split" | "standalone";
  hasResources: boolean;
  packageCount: number | null;
  typeStringCount: number | null;
  typeIds: number[];
  styledStringPoolCount: number;
  warnings: string[];
  unsupported: string[];
};

type SampleShape = {
  path: string;
  ok: boolean;
  apkCount: number;
  baseApk: string | null;
  unsupported: string[];
  warnings: string[];
  apks: ApkShape[];
};

const args = process.argv.slice(2);
const reportIndex = args.indexOf("--report");
const reportPath = reportIndex >= 0 ? args[reportIndex + 1] : undefined;
const manifestIndex = args.indexOf("--manifest");
const manifestPath = manifestIndex >= 0 ? args[manifestIndex + 1] : undefined;
const directInputs = args.filter((arg, index) => index !== reportIndex && index !== reportIndex + 1 && index !== manifestIndex && index !== manifestIndex + 1);
const manifestInputs = manifestPath ? await readManifest(manifestPath) : [];
const inputs = [...new Set([...directInputs, ...manifestInputs])];

if (inputs.length === 0) {
  throw new Error("Pass one or more APK/XAPK/APKS/APKM/ZIP paths or --manifest <file>.");
}

const results = await Promise.all(inputs.map((path) => scanSample(path)));
for (const result of results) {
  console.log(`${result.ok ? "PASS" : "WARN"} ${result.path}`);
  console.log(JSON.stringify({
    apkCount: result.apkCount,
    baseApk: result.baseApk,
    unsupported: result.unsupported,
    warnings: result.warnings,
    apks: result.apks
  }, null, 2));
}

if (reportPath) {
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, renderMarkdown(results));
  const jsonPath = reportPath.replace(/\.md$/i, ".json");
  await writeFile(jsonPath, `${JSON.stringify(renderJson(results), null, 2)}\n`);
  console.log(`Wrote ${reportPath}`);
  console.log(`Wrote ${jsonPath}`);
}

async function scanSample(path: string): Promise<SampleShape> {
  const bytes = new Uint8Array(await readFile(path));
  const apkEntries = extractApks(path, bytes);
  const base = chooseBase(apkEntries);
  const baseShape = base ? inspectApk(base.name, base.bytes, apkEntries.length === 1 ? "standalone" : "base") : null;
  const baseTypeStringCount = baseShape?.typeStringCount ?? null;
  const apks = apkEntries.map((apk) => {
    const role = apk === base ? (apkEntries.length === 1 ? "standalone" : "base") : "split";
    const shape = inspectApk(apk.name, apk.bytes, role);
    if (role === "split" && baseTypeStringCount !== null) {
      const absent = shape.typeIds.filter((typeId) => typeId < 1 || typeId > baseTypeStringCount);
      if (absent.length > 0) {
        shape.unsupported.push(`type ID(s) absent from base type string pool: ${[...new Set(absent)].sort((a, b) => a - b).join(", ")}`);
      }
    }
    return shape;
  });
  const unsupported = apks.flatMap((apk) => apk.unsupported.map((message) => `${apk.name}: ${message}`));
  const warnings = apks.flatMap((apk) => apk.warnings.map((message) => `${apk.name}: ${message}`));
  return {
    path,
    ok: unsupported.length === 0,
    apkCount: apkEntries.length,
    baseApk: base?.name ?? null,
    unsupported,
    warnings,
    apks
  };
}

function extractApks(path: string, bytes: Uint8Array): Array<{ name: string; bytes: Uint8Array }> {
  if (/\.apk$/i.test(path)) {
    return [{ name: basename(path), bytes }];
  }
  const files = unzipSync(bytes);
  return Object.entries(files)
    .filter(([name]) => /\.apk$/i.test(name))
    .map(([name, apkBytes]) => ({ name, bytes: apkBytes }))
    .sort((a, b) => b.bytes.length - a.bytes.length);
}

function chooseBase(apks: Array<{ name: string; bytes: Uint8Array }>): { name: string; bytes: Uint8Array } | null {
  return apks.find((apk) => !basename(apk.name).startsWith("config.") && !basename(apk.name).startsWith("split.")) ?? apks[0] ?? null;
}

function inspectApk(name: string, apkBytes: Uint8Array, role: ApkShape["role"]): ApkShape {
  const files = unzipSync(apkBytes, { filter: (file) => file.name === "resources.arsc" });
  const resources = files["resources.arsc"];
  if (!resources) {
    return { name, role, hasResources: false, packageCount: null, typeStringCount: null, typeIds: [], styledStringPoolCount: 0, warnings: [], unsupported: [] };
  }
  const shape = inspectResourceTable(resources);
  const unsupported: string[] = [];
  if (shape.packageCount !== 1) {
    unsupported.push(`multi-package table (${shape.packageCount} package(s))`);
  }
  if (shape.styledStringPoolCount > 0) {
    unsupported.push(`${shape.styledStringPoolCount} styled string pool(s) require span remapping`);
  }
  return { name, role, hasResources: true, ...shape, unsupported };
}

function inspectResourceTable(bytes: Uint8Array): Omit<ApkShape, "name" | "role" | "hasResources" | "unsupported"> {
  const warnings: string[] = [];
  if (readU16(bytes, 0) !== 0x0002) {
    return { packageCount: 0, typeStringCount: null, typeIds: [], styledStringPoolCount: 0, warnings: ["resources.arsc is not a RES_TABLE_TYPE chunk."] };
  }
  const tableSize = Math.min(readU32(bytes, 4), bytes.length);
  const packageCount = readU32(bytes, 8);
  let cursor = readU16(bytes, 2);
  let styledStringPoolCount = 0;
  let typeStringCount: number | null = null;
  const typeIds: number[] = [];

  while (cursor + 8 <= tableSize) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > bytes.length) {
      warnings.push(`Malformed top-level chunk at ${cursor}.`);
      break;
    }
    if (type === 0x0001 && stringPoolHasStyles(bytes, cursor)) {
      styledStringPoolCount++;
    } else if (type === 0x0200) {
      const packageShape = inspectPackage(bytes, cursor);
      styledStringPoolCount += packageShape.styledStringPoolCount;
      typeStringCount ??= packageShape.typeStringCount;
      typeIds.push(...packageShape.typeIds);
      warnings.push(...packageShape.warnings);
    }
    cursor += size;
  }

  return { packageCount, typeStringCount, typeIds: [...new Set(typeIds)].sort((a, b) => a - b), styledStringPoolCount, warnings };
}

function inspectPackage(bytes: Uint8Array, offset: number): { typeStringCount: number | null; typeIds: number[]; styledStringPoolCount: number; warnings: string[] } {
  const warnings: string[] = [];
  const packageEnd = offset + readU32(bytes, offset + 4);
  const packageHeaderSize = readU16(bytes, offset + 2);
  const typeStringPoolOffset = offset + readU32(bytes, offset + 268);
  const typeStringCount = readU32(bytes, typeStringPoolOffset + 8);
  let styledStringPoolCount = 0;
  const typeIds: number[] = [];
  let cursor = offset + packageHeaderSize;

  while (cursor + 8 <= packageEnd) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > packageEnd) {
      warnings.push(`Malformed package child chunk at ${cursor}.`);
      break;
    }
    if (type === 0x0001 && stringPoolHasStyles(bytes, cursor)) {
      styledStringPoolCount++;
    }
    if (type === 0x0201 || type === 0x0202) {
      typeIds.push(bytes[cursor + 8]);
    }
    cursor += size;
  }

  return { typeStringCount, typeIds: [...new Set(typeIds)].sort((a, b) => a - b), styledStringPoolCount, warnings };
}

function stringPoolHasStyles(bytes: Uint8Array, offset: number): boolean {
  return offset + 16 <= bytes.length && readU32(bytes, offset + 12) > 0;
}

async function readManifest(path: string): Promise<string[]> {
  const text = await readFile(path, "utf8");
  return text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith("#"));
}

function renderMarkdown(results: SampleShape[]): string {
  const passed = results.filter((result) => result.ok).length;
  return [
    "# ARSC Shape Report",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    `Summary: ${passed}/${results.length} sample(s) have no currently unsupported ARSC shape.`,
    "",
    "| Status | Path | APKs | Base APK | Unsupported | Warnings |",
    "| --- | --- | ---: | --- | --- | --- |",
    ...results.map((result) => `| ${result.ok ? "PASS" : "WARN"} | \`${result.path}\` | ${result.apkCount} | ${result.baseApk ?? ""} | ${escapeTable(result.unsupported.join("<br>"))} | ${escapeTable(result.warnings.join("<br>"))} |`),
    "",
    "## APK Details",
    "",
    "| Sample | APK | Role | Packages | Type strings | Type IDs | Styled pools | Unsupported |",
    "| --- | --- | --- | ---: | ---: | --- | ---: | --- |",
    ...results.flatMap((result) => result.apks.map((apk) => `| \`${result.path}\` | ${apk.name} | ${apk.role} | ${apk.packageCount ?? ""} | ${apk.typeStringCount ?? ""} | ${apk.typeIds.join(", ")} | ${apk.styledStringPoolCount} | ${escapeTable(apk.unsupported.join("<br>"))} |`)),
    ""
  ].join("\n");
}

function renderJson(results: SampleShape[]) {
  return {
    generatedAt: new Date().toISOString(),
    summary: {
      passed: results.filter((result) => result.ok).length,
      total: results.length
    },
    results
  };
}

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

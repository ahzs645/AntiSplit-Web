import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

type FdroidIndex = {
  packages: Record<string, FdroidPackage>;
};

type FdroidPackage = {
  metadata?: {
    license?: string;
    sourceCode?: string;
    categories?: string[];
  };
  versions?: Record<string, FdroidVersion>;
};

type FdroidVersion = {
  added?: number;
  file?: {
    name?: string;
    sha256?: string;
    size?: number;
  };
  manifest?: {
    versionName?: string;
    versionCode?: number;
    usesSdk?: {
      minSdkVersion?: number;
      targetSdkVersion?: number;
    };
  };
  antiFeatures?: Record<string, unknown>;
};

type CorpusEntry = {
  packageName: string;
  versionName: string;
  versionCode: number | null;
  license: string;
  sourceCode: string;
  apkName: string;
  apkUrl: string;
  localPath: string;
  bytes: number;
  sha256: string;
  downloaded: boolean;
};

const args = process.argv.slice(2);
const limit = readNumberArg("--limit", 17);
const maxBytes = readNumberArg("--max-bytes", 8 * 1024 * 1024);
const outputDir = readStringArg("--output-dir", join(process.env.HOME ?? "/tmp", "Downloads", "antisplit-fdroid-corpus"));
const manifestPath = readStringArg("--manifest", "docs/fdroid-corpus-manifest.txt");
const reportPath = readStringArg("--report", "docs/fdroid-corpus-report.md");
const indexUrl = readStringArg("--index-url", "https://f-droid.org/repo/index-v2.json");
const repoBaseUrl = readStringArg("--repo-url", "https://f-droid.org/repo");
const dryRun = args.includes("--dry-run");

console.log(`Fetching F-Droid index: ${indexUrl}`);
const index = await fetchJson<FdroidIndex>(indexUrl);
const selected = selectCorpus(index, limit, maxBytes, repoBaseUrl, outputDir);

if (selected.length < limit) {
  console.warn(`Only found ${selected.length} APK candidate(s) under ${maxBytes} bytes.`);
}

const entries: CorpusEntry[] = [];
await mkdir(outputDir, { recursive: true });
for (const entry of selected) {
  if (dryRun) {
    entries.push({ ...entry, downloaded: false });
    continue;
  }
  const bytes = await downloadBytes(entry.apkUrl);
  const digest = sha256(bytes);
  if (digest !== entry.sha256) {
    throw new Error(`SHA-256 mismatch for ${entry.apkUrl}: expected ${entry.sha256}, got ${digest}`);
  }
  if (bytes.byteLength !== entry.bytes) {
    throw new Error(`Size mismatch for ${entry.apkUrl}: expected ${entry.bytes}, got ${bytes.byteLength}`);
  }
  await writeFile(entry.localPath, bytes);
  entries.push({ ...entry, downloaded: true });
  console.log(`Downloaded ${entry.packageName} ${entry.versionName}: ${entry.localPath}`);
}

await mkdir(dirname(manifestPath), { recursive: true });
await writeFile(manifestPath, `${entries.map((entry) => entry.localPath).join("\n")}\n`);
await mkdir(dirname(reportPath), { recursive: true });
await writeFile(reportPath, renderMarkdown(entries));
await writeFile(reportPath.replace(/\.md$/i, ".json"), `${JSON.stringify(renderJson(entries), null, 2)}\n`);

console.log(`Wrote ${manifestPath}`);
console.log(`Wrote ${reportPath}`);
console.log(`Wrote ${reportPath.replace(/\.md$/i, ".json")}`);

function selectCorpus(index: FdroidIndex, count: number, sizeLimit: number, baseUrl: string, directory: string): CorpusEntry[] {
  const candidates: CorpusEntry[] = [];
  for (const [packageName, packageInfo] of Object.entries(index.packages)) {
    const version = pickVersion(packageInfo, sizeLimit);
    if (!version?.file?.name || !version.file.sha256 || !version.file.size) {
      continue;
    }
    const apkName = basename(version.file.name);
    candidates.push({
      packageName,
      versionName: version.manifest?.versionName ?? "",
      versionCode: version.manifest?.versionCode ?? null,
      license: packageInfo.metadata?.license ?? "",
      sourceCode: packageInfo.metadata?.sourceCode ?? "",
      apkName,
      apkUrl: `${baseUrl}${version.file.name}`,
      localPath: join(directory, apkName),
      bytes: version.file.size,
      sha256: version.file.sha256,
      downloaded: false
    });
  }

  return candidates
    .sort((a, b) => {
      const licenseScore = scoreLicense(b.license) - scoreLicense(a.license);
      if (licenseScore !== 0) return licenseScore;
      return a.bytes - b.bytes;
    })
    .slice(0, count);
}

function pickVersion(packageInfo: FdroidPackage, sizeLimit: number): FdroidVersion | null {
  const versions = Object.values(packageInfo.versions ?? {})
    .filter((version) => version.file?.name?.endsWith(".apk"))
    .filter((version) => version.file?.size !== undefined && version.file.size <= sizeLimit)
    .filter((version) => Object.keys(version.antiFeatures ?? {}).length === 0)
    .sort((a, b) => (b.added ?? 0) - (a.added ?? 0));
  return versions[0] ?? null;
}

function scoreLicense(license: string): number {
  if (/^(apache|mit|bsd|isc)/i.test(license)) return 3;
  if (/gpl|lgpl|agpl/i.test(license)) return 2;
  return license ? 1 : 0;
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: { "user-agent": "AntiSplit-Web corpus fetcher" } });
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: HTTP ${response.status}`);
  }
  return await response.json() as T;
}

async function downloadBytes(url: string): Promise<Uint8Array> {
  const response = await fetch(url, { headers: { "user-agent": "AntiSplit-Web corpus fetcher" } });
  if (!response.ok) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

function readStringArg(name: string, fallback: string): string {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] ?? fallback : fallback;
}

function readNumberArg(name: string, fallback: number): number {
  const value = readStringArg(name, String(fallback));
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number.`);
  }
  return parsed;
}

function renderMarkdown(entries: CorpusEntry[]): string {
  return [
    "# F-Droid Corpus",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    `Output directory: \`${outputDir}\``,
    "",
    "| Package | Version | Bytes | SHA-256 | License | APK | Downloaded |",
    "| --- | --- | ---: | --- | --- | --- | --- |",
    ...entries.map((entry) => `| \`${entry.packageName}\` | ${escapeTable(entry.versionName)} | ${entry.bytes} | \`${entry.sha256}\` | ${escapeTable(entry.license)} | \`${entry.localPath}\` | ${entry.downloaded ? "yes" : "no"} |`),
    ""
  ].join("\n");
}

function renderJson(entries: CorpusEntry[]) {
  return {
    generatedAt: new Date().toISOString(),
    source: {
      indexUrl,
      repoBaseUrl,
      outputDir,
      maxBytes,
      requestedLimit: limit
    },
    summary: {
      selected: entries.length,
      downloaded: entries.filter((entry) => entry.downloaded).length
    },
    entries
  };
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function escapeTable(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

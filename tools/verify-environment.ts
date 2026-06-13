import { access, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { verifyWithApkSigner } from "./apksigner";

type CommandLookup = {
  command: string;
  found: boolean;
  path?: string;
  checked: string[];
};

const outputPath = "docs/environment-check.json";
const sdkRoots = [
  process.env.ANDROID_HOME,
  process.env.ANDROID_SDK_ROOT,
  "/opt/homebrew/share/android-commandlinetools",
  "/usr/local/share/android-commandlinetools",
  join(process.env.HOME ?? "", "Library", "Android", "sdk"),
  join(process.env.HOME ?? "", "Android", "Sdk")
].filter((value, index, values): value is string => Boolean(value) && values.indexOf(value) === index);

const apksignerProbeApk = "dist-fixtures/REON+POCKET_2.2.0_APKPure_antisplit_v2.apk";
const apksigner = await verifyWithApkSigner(apksignerProbeApk);
const sdkmanager = await findCommand("sdkmanager");
const java = await findCommand("java");
const javac = await findCommand("javac");
const sdkRootChecks = await Promise.all(sdkRoots.map(async (root) => ({
  root,
  exists: await exists(root),
  buildTools: await exists(join(root, "build-tools")),
  cmdlineTools: await exists(join(root, "cmdline-tools"))
})));

const report = {
  generatedAt: new Date().toISOString(),
  environment: {
    PATHDirectoryCount: (process.env.PATH ?? "").split(delimiter).filter(Boolean).length,
    ANDROID_HOME: process.env.ANDROID_HOME ?? null,
    ANDROID_SDK_ROOT: process.env.ANDROID_SDK_ROOT ?? null,
    JAVA_HOME: process.env.JAVA_HOME ?? null
  },
  commands: {
    java,
    javac,
    sdkmanager
  },
  sdkRoots: sdkRootChecks,
  apksigner: {
    probeApk: apksignerProbeApk,
    available: apksigner.available,
    command: apksigner.command ?? null,
    ok: apksigner.ok,
    skippedReason: apksigner.skippedReason ?? null,
    stdout: apksigner.stdout,
    stderr: apksigner.stderr
  }
};

await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
console.log(`Wrote ${outputPath}`);

async function findCommand(command: string): Promise<CommandLookup> {
  const checked: string[] = [];
  for (const dir of (process.env.PATH ?? "").split(delimiter).filter(Boolean)) {
    const candidate = join(dir, command);
    checked.push(candidate);
    if (await exists(candidate)) {
      return { command, found: true, path: candidate, checked };
    }
  }
  return { command, found: false, checked };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

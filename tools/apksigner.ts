import { access } from "node:fs/promises";
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";

export type ApkSignerResult = {
  available: boolean;
  command?: string;
  ok: boolean;
  skippedReason?: string;
  stdout: string;
  stderr: string;
};

const SDK_ROOT_CANDIDATES = [
  process.env.ANDROID_HOME,
  process.env.ANDROID_SDK_ROOT,
  "/opt/homebrew/share/android-commandlinetools",
  "/usr/local/share/android-commandlinetools",
  join(process.env.HOME ?? "", "Library", "Android", "sdk"),
  join(process.env.HOME ?? "", "Android", "Sdk")
].filter((value, index, values): value is string => Boolean(value) && values.indexOf(value) === index);

const JAVA_HOME_CANDIDATES = [
  process.env.JAVA_HOME,
  "/opt/homebrew/opt/openjdk",
  "/usr/local/opt/openjdk"
].filter((value, index, values): value is string => Boolean(value) && values.indexOf(value) === index);

export async function verifyWithApkSigner(apkPath: string): Promise<ApkSignerResult> {
  const lookup = await findApkSigner();
  if (!lookup.command) {
    const pathCount = (process.env.PATH ?? "").split(delimiter).filter(Boolean).length;
    const sdkLocations = SDK_ROOT_CANDIDATES.flatMap((root) => [join(root, "build-tools"), join(root, "cmdline-tools")]);
    return {
      available: false,
      ok: false,
      skippedReason: `Android apksigner was not found. Checked ${pathCount} PATH director${pathCount === 1 ? "y" : "ies"} and SDK locations: ${sdkLocations.join(", ")}.`,
      stdout: "",
      stderr: ""
    };
  }

  const result = spawnSync(lookup.command, ["verify", "--verbose", apkPath], {
    encoding: "utf8",
    env: buildJavaEnv()
  });
  return {
    available: true,
    command: lookup.command,
    ok: result.status === 0,
    stdout: result.stdout,
    stderr: result.stderr
  };
}

function buildJavaEnv(): NodeJS.ProcessEnv {
  const javaHome = JAVA_HOME_CANDIDATES.find((candidate) => {
    return existsSync(join(candidate, "bin", "java"));
  });
  if (!javaHome) {
    return process.env;
  }
  return {
    ...process.env,
    JAVA_HOME: javaHome,
    PATH: `${join(javaHome, "bin")}${delimiter}${process.env.PATH ?? ""}`
  };
}

async function findApkSigner(): Promise<{ command: string | null; checked: string[] }> {
  const checked: string[] = [];
  const pathHit = await findOnPath("apksigner", checked);
  if (pathHit) {
    return { command: pathHit, checked };
  }

  for (const sdkRoot of SDK_ROOT_CANDIDATES) {
    const candidates = [
      join(sdkRoot, "build-tools"),
      join(sdkRoot, "cmdline-tools")
    ];
    for (const base of candidates) {
      const found = await findUnder(base, "apksigner", checked);
      if (found) {
        return { command: found, checked };
      }
    }
  }

  return { command: null, checked };
}

async function findOnPath(command: string, checked: string[]): Promise<string | null> {
  const paths = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  for (const dir of paths) {
    const candidate = join(dir, command);
    checked.push(candidate);
    if (await isExecutable(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function findUnder(root: string, fileName: string, checked: string[]): Promise<string | null> {
  const { readdir } = await import("node:fs/promises");
  try {
    checked.push(root);
    const entries = await readdir(root, { withFileTypes: true });
    const direct = entries.find((entry) => entry.isFile() && entry.name === fileName);
    if (direct) {
      const path = join(root, direct.name);
      checked.push(path);
      return (await isExecutable(path)) ? path : null;
    }
    for (const entry of entries.filter((entry) => entry.isDirectory()).sort((a, b) => b.name.localeCompare(a.name))) {
      const found = await findUnder(join(root, entry.name), fileName, checked);
      if (found) {
        return found;
      }
    }
  } catch {
    return null;
  }
  return null;
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

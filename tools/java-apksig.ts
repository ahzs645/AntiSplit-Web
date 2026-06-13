import { access, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { spawnFile } from "./process";

export type JavaApkSigResult = {
  available: boolean;
  ok: boolean;
  skippedReason?: string;
  verified?: boolean;
  verifiedUsingV1?: boolean;
  verifiedUsingV2?: boolean;
  verifiedUsingV3?: boolean;
  verifiedUsingV31?: boolean;
  verifiedUsingV4?: boolean;
  signerCertificateCount?: number;
  v1SignerCount?: number;
  v2SignerCount?: number;
  v3SignerCount?: number;
  errors?: string[];
  warnings?: string[];
  stdout: string;
  stderr: string;
};

let compiledVerifier: Promise<void> | null = null;

export async function verifyWithBundledApkSig(apkPath: string, minSdk?: number, maxSdk?: number, v4SignaturePath?: string): Promise<JavaApkSigResult> {
  const javaHome = await findJavaHome();
  if (!javaHome) {
    return {
      available: false,
      ok: false,
      skippedReason: "Could not find a JDK. Install OpenJDK or set JAVA_HOME to a JDK with java and javac.",
      stdout: "",
      stderr: ""
    };
  }

  compiledVerifier ??= compileVerifier(javaHome);
  await compiledVerifier;
  const args = [
    "-cp",
    "build/java-tools/classes",
    "VerifyApkWithApksig",
    apkPath
  ];
  if (minSdk !== undefined) {
    args.push(String(minSdk));
  }
  if (maxSdk !== undefined) {
    args.push(String(maxSdk));
  }
  if (v4SignaturePath !== undefined) {
    if (minSdk === undefined) {
      args.push("");
    }
    if (maxSdk === undefined) {
      args.push("");
    }
    args.push(v4SignaturePath);
  }
  const run = await spawnCapture(join(javaHome, "bin", "java"), args);
  let parsed: Partial<JavaApkSigResult> = {};
  try {
    parsed = JSON.parse(run.stdout);
  } catch {
    parsed = {};
  }
  return {
    available: true,
    ok: run.code === 0 && parsed.verified === true,
    ...parsed,
    stdout: run.stdout,
    stderr: run.stderr
  };
}

async function findJavaHome(): Promise<string | null> {
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
  return null;
}

async function compileVerifier(javaHome: string): Promise<void> {
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
    "tools/java/VerifyApkWithApksig.java"
  ]);
}

function spawnCapture(command: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      });
    });
  });
}

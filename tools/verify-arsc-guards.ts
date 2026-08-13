import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { unzipSync, zipSync } from "fflate";
import { tryMergeResourceTables } from "../src/arscMerger";

const fixturePath = process.argv[2] ?? "/Users/ahmadjalil/Downloads/iHunter+BC_5.0.69_APKPure.xapk";

type GuardCase = {
  name: string;
  splitBytes: Uint8Array;
  expectedUnsupported: string;
};

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function writeU32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function findTopLevelChunk(bytes: Uint8Array, wantedType: number): number {
  const tableSize = Math.min(readU32(bytes, 4), bytes.length);
  let cursor = readU16(bytes, 2);
  while (cursor + 8 <= tableSize) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > bytes.length) {
      throw new Error(`Malformed top-level ARSC chunk at ${cursor}`);
    }
    if (type === wantedType) {
      return cursor;
    }
    cursor += size;
  }
  throw new Error(`Top-level ARSC chunk 0x${wantedType.toString(16)} was not found`);
}

function findPackageChildChunk(bytes: Uint8Array, wantedType: number): number {
  const packageOffset = findTopLevelChunk(bytes, 0x0200);
  const packageHeaderSize = readU16(bytes, packageOffset + 2);
  const packageEnd = packageOffset + readU32(bytes, packageOffset + 4);
  let cursor = packageOffset + packageHeaderSize;
  while (cursor + 8 <= packageEnd) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > packageEnd) {
      throw new Error(`Malformed package child ARSC chunk at ${cursor}`);
    }
    if (type === wantedType) {
      return cursor;
    }
    cursor += size;
  }
  throw new Error(`Package child ARSC chunk 0x${wantedType.toString(16)} was not found`);
}

function replaceResourceTable(apkBytes: Uint8Array, mutate: (resources: Uint8Array) => void): Uint8Array {
  const files = unzipSync(apkBytes);
  const resources = files["resources.arsc"];
  if (!resources) {
    throw new Error("APK has no resources.arsc");
  }
  const mutated = new Uint8Array(resources);
  mutate(mutated);
  files["resources.arsc"] = mutated;
  return zipSync(files, { level: 0 });
}

function pickApks(xapkBytes: Uint8Array): { baseName: string; baseBytes: Uint8Array; splitName: string; splitBytes: Uint8Array } {
  const files = unzipSync(xapkBytes);
  const apkEntries = Object.entries(files).filter(([name]) => name.endsWith(".apk"));
  const base = apkEntries.find(([name]) => !basename(name).startsWith("config."));
  const split = apkEntries.find(([name, bytes]) => basename(name).startsWith("config.") && Boolean(unzipSync(bytes)["resources.arsc"]));
  if (!base || !split) {
    throw new Error("Fixture must contain one base APK and at least one resource split APK");
  }
  return {
    baseName: base[0],
    baseBytes: base[1],
    splitName: split[0],
    splitBytes: split[1]
  };
}

function assertGuard(baseBytes: Uint8Array, guardCase: GuardCase): void {
  const result = tryMergeResourceTables(baseBytes, [{ name: guardCase.name, bytes: guardCase.splitBytes }]);
  if (!result) {
    throw new Error(`${guardCase.name}: merger returned no plan`);
  }
  if (result.mergedBytes) {
    throw new Error(`${guardCase.name}: unsupported table unexpectedly merged`);
  }
  const combined = [...result.unsupported, ...result.diagnostics].join("\n");
  if (!combined.includes(guardCase.expectedUnsupported)) {
    throw new Error(`${guardCase.name}: expected unsupported reason containing "${guardCase.expectedUnsupported}", got:\n${combined}`);
  }
}

async function main(): Promise<void> {
  const fixtureBytes = new Uint8Array(await readFile(fixturePath));
  const { baseName, baseBytes, splitName, splitBytes } = pickApks(fixtureBytes);

  const positiveControl = tryMergeResourceTables(baseBytes, [{ name: splitName, bytes: splitBytes }]);
  if (!positiveControl?.mergedBytes || positiveControl.unsupported.length > 0) {
    throw new Error(`Positive control failed for ${splitName}: ${(positiveControl?.unsupported ?? []).join("; ")}`);
  }

  const cases: GuardCase[] = [
    {
      name: "malformed-styled-string-pool-split.apk",
      splitBytes: replaceResourceTable(splitBytes, (resources) => {
        const tableStringPoolOffset = readU16(resources, 2);
        writeU32(resources, tableStringPoolOffset + 12, 1);
      }),
      expectedUnsupported: "Invalid string pool"
    },
    {
      name: "multi-package-split.apk",
      splitBytes: replaceResourceTable(splitBytes, (resources) => {
        writeU32(resources, 8, 2);
      }),
      expectedUnsupported: "multi-package resources.arsc merge is not implemented yet"
    },
    {
      name: "missing-base-type-id-split.apk",
      splitBytes: replaceResourceTable(splitBytes, (resources) => {
        const typeSpecOffset = findPackageChildChunk(resources, 0x0202);
        resources[typeSpecOffset + 8] = 0xff;
      }),
      expectedUnsupported: "type spec 255 is absent from the base type string pool"
    }
  ];

  for (const guardCase of cases) {
    assertGuard(baseBytes, guardCase);
  }

  console.log(
    JSON.stringify(
      {
        fixture: fixturePath,
        base: baseName,
        positiveControl: splitName,
        checked: cases.map((guardCase) => guardCase.name)
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

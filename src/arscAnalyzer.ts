import { unzipSync } from "fflate";

export type ArscTypeChunkSummary = {
  typeId: number;
  flags: number;
  configSize: number;
  configQualifier: string;
  entryCount: number;
  populatedEntries: number;
  keyStringRefs: number[];
  tableStringValueRefs: number[];
};

export type ArscPackageSummary = {
  id: number;
  name: string;
  typeCount: number;
  keyCount: number;
  typeStringPoolHash: string;
  keyStringPoolHash: string;
  typeStrings: string[];
  keyStrings: string[];
  typeChunks: ArscTypeChunkSummary[];
};

export type ArscSummary = {
  byteLength: number;
  packageCount: number;
  tableStrings: string[];
  packages: ArscPackageSummary[];
  warnings: string[];
};

export type ResourceMergeCompatibility = {
  canAppendTypeChunks: boolean;
  reasons: string[];
};

const RES_TABLE_TYPE = 0x0002;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_TABLE_PACKAGE_TYPE = 0x0200;
const RES_TABLE_TYPE_TYPE = 0x0201;

export function analyzeApkResourceTable(apkBytes: Uint8Array): ArscSummary | null {
  const entries = unzipSync(apkBytes, {
    filter: (file) => file.name === "resources.arsc"
  });
  const resourceTable = entries["resources.arsc"];
  if (!resourceTable) {
    return null;
  }
  return analyzeResourceTable(resourceTable);
}

export function analyzeResourceTable(bytes: Uint8Array): ArscSummary {
  const warnings: string[] = [];
  if (readU16(bytes, 0) !== RES_TABLE_TYPE) {
    return {
      byteLength: bytes.byteLength,
      packageCount: 0,
      tableStrings: [],
      packages: [],
      warnings: ["resources.arsc does not start with a RES_TABLE_TYPE chunk."]
    };
  }

  const tableSize = readU32(bytes, 4);
  const packageCount = readU32(bytes, 8);
  const packages: ArscPackageSummary[] = [];
  let tableStrings: string[] = [];
  let cursor = readU16(bytes, 2);

  while (cursor + 8 <= Math.min(bytes.length, tableSize)) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > bytes.length) {
      warnings.push(`Invalid ARSC chunk at offset ${cursor}.`);
      break;
    }

    if (type === RES_STRING_POOL_TYPE && tableStrings.length === 0) {
      tableStrings = parseStringPool(bytes, cursor, warnings);
    } else if (type === RES_TABLE_PACKAGE_TYPE) {
      packages.push(parsePackage(bytes, cursor, warnings));
    }

    cursor += size;
  }

  return {
    byteLength: bytes.byteLength,
    packageCount,
    tableStrings,
    packages,
    warnings
  };
}

export function analyzeResourceMergeCompatibility(baseApkBytes: Uint8Array, splitApks: Array<{ name: string; bytes: Uint8Array }>): ResourceMergeCompatibility {
  const base = analyzeApkResourceTable(baseApkBytes);
  const reasons: string[] = [];
  if (!base || base.packages.length !== 1) {
    return {
      canAppendTypeChunks: false,
      reasons: ["Base APK does not have exactly one analyzable resources.arsc package."]
    };
  }

  const basePackage = base.packages[0];
  const baseTypeStringSet = new Set(basePackage.typeStrings);
  const baseKeyStringSet = new Set(basePackage.keyStrings);
  const baseTableStringSet = new Set(base.tableStrings);
  for (const split of splitApks) {
    const splitSummary = analyzeApkResourceTable(split.bytes);
    if (!splitSummary) {
      continue;
    }
    if (splitSummary.packages.length !== 1) {
      reasons.push(`${split.name}: split resources.arsc does not have exactly one package.`);
      continue;
    }
    const splitPackage = splitSummary.packages[0];
    if (splitPackage.id !== basePackage.id || splitPackage.name !== basePackage.name) {
      reasons.push(`${split.name}: package identity differs from base (${splitPackage.name || splitPackage.id}).`);
    }
    if (splitPackage.typeStringPoolHash !== basePackage.typeStringPoolHash) {
      const missingTypes = uniqueStrings(splitPackage.typeStrings.filter((value) => !baseTypeStringSet.has(value)));
      reasons.push(`${split.name}: type string pool differs from base; ${formatMissingCount(missingTypes)} type name(s) require remapping before type-chunk append.`);
    }
    if (splitPackage.keyStringPoolHash !== basePackage.keyStringPoolHash) {
      const usedKeys = uniqueNumbers(splitPackage.typeChunks.flatMap((chunk) => chunk.keyStringRefs))
        .map((index) => splitPackage.keyStrings[index])
        .filter((value): value is string => value !== undefined);
      const missingKeys = uniqueStrings(usedKeys.filter((value) => !baseKeyStringSet.has(value)));
      reasons.push(`${split.name}: key string pool differs from base; ${usedKeys.length} used key name(s) need index remapping, ${formatMissingCount(missingKeys)} are absent from base.`);
    }
    const usedTableStrings = uniqueNumbers(splitPackage.typeChunks.flatMap((chunk) => chunk.tableStringValueRefs))
      .map((index) => splitSummary.tableStrings[index])
      .filter((value): value is string => value !== undefined);
    const missingTableStrings = uniqueStrings(usedTableStrings.filter((value) => !baseTableStringSet.has(value)));
    if (usedTableStrings.length > 0) {
      reasons.push(`${split.name}: ${usedTableStrings.length} resource value string(s) need global string-pool remapping, ${formatMissingCount(missingTableStrings)} are absent from base.`);
    }
  }

  return {
    canAppendTypeChunks: reasons.length === 0,
    reasons
  };
}

export function summarizeArsc(summary: ArscSummary): string {
  const typeChunks = summary.packages.reduce((sum, pkg) => sum + pkg.typeChunks.length, 0);
  const populatedEntries = summary.packages.reduce(
    (sum, pkg) => sum + pkg.typeChunks.reduce((inner, chunk) => inner + chunk.populatedEntries, 0),
    0
  );
  const packageNames = summary.packages.map((pkg) => pkg.name || `id-${pkg.id}`).join(", ");
  return `${formatBytes(summary.byteLength)} resources.arsc, ${summary.packageCount} package(s) (${packageNames}), ${typeChunks} type config chunk(s), ${populatedEntries} populated entr${populatedEntries === 1 ? "y" : "ies"}`;
}

function parsePackage(bytes: Uint8Array, offset: number, warnings: string[]): ArscPackageSummary {
  const size = readU32(bytes, offset + 4);
  const headerSize = readU16(bytes, offset + 2);
  const id = readU32(bytes, offset + 8);
  const name = readUtf16Fixed(bytes, offset + 12, 128);
  const typeStringPoolOffset = readU32(bytes, offset + 268);
  const typeStringPoolCount = readU32(bytes, offset + 272);
  const keyStringPoolOffset = readU32(bytes, offset + 276);
  const keyStringPoolCount = readU32(bytes, offset + 280);
  const typeStrings = parseStringPool(bytes, offset + typeStringPoolOffset, warnings);
  const keyStrings = parseStringPool(bytes, offset + keyStringPoolOffset, warnings);
  const typeChunks: ArscTypeChunkSummary[] = [];
  let cursor = offset + headerSize;

  while (cursor + 8 <= offset + size) {
    const type = readU16(bytes, cursor);
    const chunkHeaderSize = readU16(bytes, cursor + 2);
    const chunkSize = readU32(bytes, cursor + 4);
    if (chunkSize < chunkHeaderSize || cursor + chunkSize > offset + size) {
      warnings.push(`Invalid package child chunk at offset ${cursor}.`);
      break;
    }

    if (type === RES_TABLE_TYPE_TYPE) {
      typeChunks.push(parseTypeChunk(bytes, cursor));
    }

    cursor += chunkSize;
  }

  return {
    id,
    name,
    typeCount: Math.max(typeStringPoolCount, countStringPool(bytes, offset + typeStringPoolOffset)),
    keyCount: Math.max(keyStringPoolCount, countStringPool(bytes, offset + keyStringPoolOffset)),
    typeStringPoolHash: hashChunk(bytes, offset + typeStringPoolOffset),
    keyStringPoolHash: hashChunk(bytes, offset + keyStringPoolOffset),
    typeStrings,
    keyStrings,
    typeChunks
  };
}

function hashChunk(bytes: Uint8Array, offset: number): string {
  if (offset <= 0 || offset + 8 > bytes.length) {
    return "missing";
  }
  const size = readU32(bytes, offset + 4);
  if (size < 8 || offset + size > bytes.length) {
    return "invalid";
  }
  let hash = 0x811c9dc5;
  for (let i = offset; i < offset + size; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function parseTypeChunk(bytes: Uint8Array, offset: number): ArscTypeChunkSummary {
  const headerSize = readU16(bytes, offset + 2);
  const size = readU32(bytes, offset + 4);
  const typeId = bytes[offset + 8];
  const flags = bytes[offset + 9];
  const entryCount = readU32(bytes, offset + 12);
  const entriesStart = readU32(bytes, offset + 16);
  const configSize = readU32(bytes, offset + 20);
  const offsetType = flags & 0x03;
  const offsetsStart = offset + headerSize;
  let populatedEntries = 0;
  const keyStringRefs: number[] = [];
  const tableStringValueRefs: number[] = [];

  if (offsetType === 0x01) {
    const sparseCount = Math.max(0, Math.floor((entriesStart - headerSize) / 4));
    populatedEntries = sparseCount;
    for (let i = 0; i < sparseCount; i++) {
      const entryOffset = readU16(bytes, offsetsStart + i * 4 + 2) * 4;
      inspectEntry(bytes, offset + entriesStart + entryOffset, offset + size, keyStringRefs, tableStringValueRefs);
    }
  } else if (offsetType === 0x02) {
    for (let i = 0; i < entryCount; i++) {
      const entryOffset = readU16(bytes, offsetsStart + i * 2);
      if (entryOffset !== 0xffff) {
        populatedEntries++;
        inspectEntry(bytes, offset + entriesStart + entryOffset * 4, offset + size, keyStringRefs, tableStringValueRefs);
      }
    }
  } else {
    for (let i = 0; i < entryCount; i++) {
      const entryOffset = readU32(bytes, offsetsStart + i * 4);
      if (entryOffset !== 0xffffffff) {
        populatedEntries++;
        inspectEntry(bytes, offset + entriesStart + entryOffset, offset + size, keyStringRefs, tableStringValueRefs);
      }
    }
  }

  return {
    typeId,
    flags,
    configSize,
    configQualifier: summarizeConfig(bytes.slice(offset + 20, Math.min(offset + 20 + configSize, offset + size))),
    entryCount,
    populatedEntries,
    keyStringRefs: uniqueNumbers(keyStringRefs),
    tableStringValueRefs: uniqueNumbers(tableStringValueRefs)
  };
}

function inspectEntry(bytes: Uint8Array, entryOffset: number, chunkEnd: number, keyStringRefs: number[], tableStringValueRefs: number[]): void {
  if (entryOffset + 8 > chunkEnd) {
    return;
  }
  const entrySize = readU16(bytes, entryOffset);
  const flags = readU16(bytes, entryOffset + 2);
  keyStringRefs.push(readU32(bytes, entryOffset + 4));
  if ((flags & 0x0001) !== 0) {
    if (entryOffset + entrySize + 8 > chunkEnd) {
      return;
    }
    const parentAndCountOffset = entryOffset + entrySize;
    const count = readU32(bytes, parentAndCountOffset + 4);
    let cursor = parentAndCountOffset + 8;
    for (let i = 0; i < count && cursor + 12 <= chunkEnd; i++) {
      inspectValue(bytes, cursor + 4, tableStringValueRefs);
      cursor += 12;
    }
    return;
  }
  inspectValue(bytes, entryOffset + entrySize, tableStringValueRefs);
}

function inspectValue(bytes: Uint8Array, offset: number, tableStringValueRefs: number[]): void {
  if (offset + 8 > bytes.length) {
    return;
  }
  const dataType = bytes[offset + 3];
  if (dataType === 0x03) {
    tableStringValueRefs.push(readU32(bytes, offset + 4));
  }
}

function countStringPool(bytes: Uint8Array, offset: number): number {
  if (offset <= 0 || offset + 12 > bytes.length || readU16(bytes, offset) !== RES_STRING_POOL_TYPE) {
    return 0;
  }
  return readU32(bytes, offset + 8);
}

function parseStringPool(bytes: Uint8Array, offset: number, warnings: string[]): string[] {
  if (offset <= 0 || offset + 28 > bytes.length || readU16(bytes, offset) !== RES_STRING_POOL_TYPE) {
    return [];
  }
  const size = readU32(bytes, offset + 4);
  const stringCount = readU32(bytes, offset + 8);
  const flags = readU32(bytes, offset + 16);
  const stringsStart = readU32(bytes, offset + 20);
  const isUtf8 = (flags & 0x00000100) !== 0;
  if (size < 28 || offset + size > bytes.length || offset + stringsStart > offset + size) {
    warnings.push(`Invalid string pool at offset ${offset}.`);
    return [];
  }
  const strings: string[] = [];
  for (let i = 0; i < stringCount; i++) {
    const stringOffset = readU32(bytes, offset + 28 + i * 4);
    const absoluteOffset = offset + stringsStart + stringOffset;
    if (absoluteOffset >= offset + size) {
      strings.push("");
      continue;
    }
    strings.push(isUtf8 ? readUtf8String(bytes, absoluteOffset, offset + size) : readUtf16String(bytes, absoluteOffset, offset + size));
  }
  return strings;
}

function readUtf8String(bytes: Uint8Array, offset: number, end: number): string {
  const firstLength = readLength8(bytes, offset, end);
  const secondLength = readLength8(bytes, firstLength.next, end);
  const stringOffset = secondLength.next;
  const stringEnd = Math.min(stringOffset + secondLength.value, end);
  return new TextDecoder().decode(bytes.slice(stringOffset, stringEnd));
}

function readUtf16String(bytes: Uint8Array, offset: number, end: number): string {
  const length = readLength16(bytes, offset, end);
  const result: number[] = [];
  let cursor = length.next;
  for (let i = 0; i < length.value && cursor + 1 < end; i++, cursor += 2) {
    result.push(readU16(bytes, cursor));
  }
  return String.fromCharCode(...result);
}

function readLength8(bytes: Uint8Array, offset: number, end: number): { value: number; next: number } {
  if (offset >= end) {
    return { value: 0, next: offset };
  }
  const first = bytes[offset];
  if ((first & 0x80) === 0 || offset + 1 >= end) {
    return { value: first, next: offset + 1 };
  }
  return { value: ((first & 0x7f) << 8) | bytes[offset + 1], next: offset + 2 };
}

function readLength16(bytes: Uint8Array, offset: number, end: number): { value: number; next: number } {
  if (offset + 1 >= end) {
    return { value: 0, next: offset };
  }
  const first = readU16(bytes, offset);
  if ((first & 0x8000) === 0 || offset + 3 >= end) {
    return { value: first, next: offset + 2 };
  }
  return { value: ((first & 0x7fff) << 16) | readU16(bytes, offset + 2), next: offset + 4 };
}

function uniqueNumbers(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function formatMissingCount(values: string[]): string {
  if (values.length === 0) {
    return "0";
  }
  const sample = values.slice(0, 4).map((value) => JSON.stringify(value)).join(", ");
  return `${values.length} (${sample}${values.length > 4 ? ", ..." : ""})`;
}

function summarizeConfig(config: Uint8Array): string {
  if (config.length < 32) {
    return "default";
  }

  const mcc = readU16(config, 4);
  const mnc = readU16(config, 6);
  const language = decodeLocale(config[8], config[9]);
  const region = decodeLocale(config[10], config[11]);
  const density = readU16(config, 14);
  const parts: string[] = [];

  if (mcc) parts.push(`mcc${mcc}`);
  if (mnc) parts.push(`mnc${mnc}`);
  if (language) parts.push(language);
  if (region) parts.push(`r${region.toUpperCase()}`);
  if (density) parts.push(densityName(density));

  return parts.length > 0 ? parts.join("-") : "default";
}

function decodeLocale(first: number, second: number): string {
  if (first === 0 && second === 0) {
    return "";
  }
  if ((first & 0x80) === 0) {
    return String.fromCharCode(first, second).replace(/\0/g, "");
  }
  const firstChar = (first & 0x1f) + 0x61;
  const secondChar = (((second & 0x03) << 3) | ((first & 0xe0) >> 5)) + 0x61;
  const thirdChar = ((second & 0x7c) >> 2) + 0x61;
  return String.fromCharCode(firstChar, secondChar, thirdChar);
}

function densityName(density: number): string {
  const known: Record<number, string> = {
    120: "ldpi",
    160: "mdpi",
    213: "tvdpi",
    240: "hdpi",
    320: "xhdpi",
    480: "xxhdpi",
    640: "xxxhdpi",
    0xfffe: "anydpi",
    0xffff: "nodpi"
  };
  return known[density] ?? `${density}dpi`;
}

function readUtf16Fixed(bytes: Uint8Array, offset: number, chars: number): string {
  const result: number[] = [];
  for (let i = 0; i < chars; i++) {
    const code = readU16(bytes, offset + i * 2);
    if (code === 0) {
      break;
    }
    result.push(code);
  }
  return String.fromCharCode(...result);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

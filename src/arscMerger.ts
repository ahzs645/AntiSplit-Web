import { unzipSync } from "fflate";

type SplitResource = {
  name: string;
  bytes: Uint8Array;
};

type ParsedTable = {
  bytes: Uint8Array;
  headerSize: number;
  packageCount: number;
  tableStringPool: StringPoolChunk;
  packageChunk: PackageChunk;
  warnings: string[];
};

type StringPoolChunk = {
  offset: number;
  size: number;
  strings: string[];
  styles: Array<StringPoolStyle | null>;
};

type StringPoolStyle = Array<{
  nameIndex: number;
  firstChar: number;
  lastChar: number;
}>;

type PackageChunk = {
  offset: number;
  size: number;
  headerSize: number;
  id: number;
  name: string;
  typeStringPoolOffset: number;
  keyStringPoolOffset: number;
  typeStringPool: StringPoolChunk;
  keyStringPool: StringPoolChunk;
  children: ChildChunk[];
};

type ChildChunk = {
  offset: number;
  size: number;
  type: number;
};

type MergePlan = {
  mergedBytes: Uint8Array | null;
  diagnostics: string[];
  unsupported: string[];
};

const RES_TABLE_TYPE = 0x0002;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_TABLE_PACKAGE_TYPE = 0x0200;
const RES_TABLE_TYPE_TYPE = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE = 0x0202;
const UTF8_FLAG = 0x00000100;
const TYPE_STRING = 0x03;
const ENTRY_FLAG_COMPLEX = 0x0001;

export function tryMergeResourceTables(baseApkBytes: Uint8Array, splitApks: SplitResource[]): MergePlan | null {
  const unsupported: string[] = [];
  const baseResourceTable = readApkResourceTable(baseApkBytes);
  if (!baseResourceTable) {
    return null;
  }
  const base = parseResourceTable(baseResourceTable);
  if (!base) {
    return { mergedBytes: null, diagnostics: [], unsupported: ["Base resources.arsc could not be parsed by the browser ARSC merger."] };
  }
  if (base.warnings.length > 0) {
    return { mergedBytes: null, diagnostics: base.warnings.map((warning) => `base: ${warning}`), unsupported: base.warnings };
  }
  if (base.packageCount !== 1) {
    return {
      mergedBytes: null,
      diagnostics: [`base: resource table has ${base.packageCount} package(s); only single-package tables are currently mergeable.`],
      unsupported: ["Multi-package resources.arsc merge is not implemented yet."]
    };
  }

  const splitTables = splitApks
    .map((split) => {
      const bytes = readApkResourceTable(split.bytes);
      const parsed = bytes ? parseResourceTable(bytes) : null;
      return { name: split.name, hasResourceTable: Boolean(bytes), parsed };
    })
    .filter((split): split is { name: string; hasResourceTable: boolean; parsed: ParsedTable | null } => split.hasResourceTable);
  if (splitTables.length === 0) {
    return null;
  }

  const diagnostics: string[] = [];
  const tableStrings = [...base.tableStringPool.strings];
  const tableStyles = base.tableStringPool.styles.map(cloneStyle);
  const keyStrings = [...base.packageChunk.keyStringPool.strings];
  const keyStyles = base.packageChunk.keyStringPool.styles.map(cloneStyle);
  const tableStringIndex = indexStyledStrings(base.tableStringPool);
  const keyStringIndex = indexStrings(keyStrings);
  const typeSpecChunks = new Map<number, Uint8Array>();
  const appendedTypeChunks: Uint8Array[] = [];

  for (const child of base.packageChunk.children) {
    if (child.type === RES_TABLE_TYPE_SPEC_TYPE) {
      const spec = base.bytes.slice(child.offset, child.offset + child.size);
      typeSpecChunks.set(spec[8], spec);
    }
  }

  for (const split of splitTables) {
    if (!split.parsed) {
      diagnostics.push(`${split.name}: resources.arsc could not be parsed by the browser ARSC merger.`);
      unsupported.push(`${split.name}: resources.arsc parse failed.`);
      continue;
    }
    if (split.parsed.warnings.length > 0) {
      diagnostics.push(...split.parsed.warnings.map((warning) => `${split.name}: ${warning}`));
      unsupported.push(...split.parsed.warnings.map((warning) => `${split.name}: ${warning}`));
      continue;
    }
    const splitPackage = split.parsed.packageChunk;
    if (split.parsed.packageCount !== 1) {
      diagnostics.push(`${split.name}: resource table has ${split.parsed.packageCount} package(s); only single-package tables are currently mergeable.`);
      unsupported.push(`${split.name}: multi-package resources.arsc merge is not implemented yet.`);
      continue;
    }
    if (splitPackage.id !== base.packageChunk.id || splitPackage.name !== base.packageChunk.name) {
      diagnostics.push(`${split.name}: package identity is not compatible with the base resource table.`);
      unsupported.push(`${split.name}: package identity differs from the base resource table.`);
      continue;
    }

    const splitTableStringRemap = mergeStyledStringPool(
      split.parsed.tableStringPool,
      tableStrings,
      tableStyles,
      tableStringIndex
    );

    for (const chunk of splitPackage.children) {
      if (chunk.type === RES_TABLE_TYPE_SPEC_TYPE) {
        const splitSpec = split.parsed.bytes.slice(chunk.offset, chunk.offset + chunk.size);
        const typeId = splitSpec[8];
        if (typeId < 1 || typeId > base.packageChunk.typeStringPool.strings.length) {
          diagnostics.push(`${split.name}: type spec ${typeId} is not present in the base type string pool.`);
          unsupported.push(`${split.name}: type spec ${typeId} is absent from the base type string pool.`);
          continue;
        }
        typeSpecChunks.set(typeId, mergeTypeSpecChunk(typeSpecChunks.get(typeId), splitSpec));
        continue;
      }
      if (chunk.type !== RES_TABLE_TYPE_TYPE) {
        continue;
      }
      const typeId = split.parsed.bytes[chunk.offset + 8];
      if (typeId < 1 || typeId > base.packageChunk.typeStringPool.strings.length) {
        diagnostics.push(`${split.name}: type chunk ${typeId} is not present in the base type string pool.`);
        unsupported.push(`${split.name}: type chunk ${typeId} is absent from the base type string pool.`);
        continue;
      }
      const rewritten = rewriteTypeChunk(
        split.parsed.bytes.slice(chunk.offset, chunk.offset + chunk.size),
        splitPackage.keyStringPool.strings,
        splitTableStringRemap,
        keyStrings,
        keyStringIndex
      );
      if (!rewritten) {
        diagnostics.push(`${split.name}: unsupported or malformed resource type chunk ${typeId}.`);
        unsupported.push(`${split.name}: unsupported or malformed resource type chunk ${typeId}.`);
        continue;
      }
      appendedTypeChunks.push(rewritten);
    }
  }

  if (unsupported.length > 0) {
    return { mergedBytes: null, diagnostics, unsupported };
  }
  if (appendedTypeChunks.length === 0) {
    return { mergedBytes: null, diagnostics, unsupported: ["No mergeable split resource type chunks were found."] };
  }

  const normalizedTablePool = normalizeStyledStringPool(tableStrings, tableStyles);
  const remappedSplitTypeChunks: Uint8Array[] = [];
  for (const appendedTypeChunk of appendedTypeChunks) {
    const chunk = remapTypeChunkStringValues(appendedTypeChunk, normalizedTablePool.remap);
    if (!chunk) {
      return { mergedBytes: null, diagnostics, unsupported: ["A merged resource type chunk could not be remapped after styled string-pool normalization."] };
    }
    remappedSplitTypeChunks.push(chunk);
  }
  const remappedBaseTypeChunks = new Map<number, Uint8Array>();
  for (const child of base.packageChunk.children) {
    if (child.type !== RES_TABLE_TYPE_TYPE) {
      continue;
    }
    const chunk = remapTypeChunkStringValues(
      base.bytes.slice(child.offset, child.offset + child.size),
      normalizedTablePool.remap
    );
    if (!chunk) {
      return { mergedBytes: null, diagnostics, unsupported: ["A base resource type chunk could not be remapped after styled string-pool normalization."] };
    }
    remappedBaseTypeChunks.set(child.offset, chunk);
  }

  const tableStringPool = buildUtf8StringPool(normalizedTablePool.strings, normalizedTablePool.styles);
  const keyStringPool = buildUtf8StringPool(keyStrings, keyStyles);
  const rebuiltPackage = rebuildPackage(
    base.bytes,
    base.packageChunk,
    keyStringPool,
    typeSpecChunks,
    remappedBaseTypeChunks,
    remappedSplitTypeChunks
  );
  const rebuiltTable = rebuildTable(base.bytes, base, tableStringPool, rebuiltPackage);
  diagnostics.push(
    `resources.arsc merge: merged ${typeSpecChunks.size} type spec chunk(s), appended ${appendedTypeChunks.length} split type chunk(s), table strings ${base.tableStringPool.strings.length}->${tableStrings.length}, key strings ${base.packageChunk.keyStringPool.strings.length}->${keyStrings.length}.`
  );

  return {
    mergedBytes: rebuiltTable,
    diagnostics,
    unsupported: []
  };
}

function readApkResourceTable(apkBytes: Uint8Array): Uint8Array | null {
  const entries = unzipSync(apkBytes, {
    filter: (file) => file.name === "resources.arsc"
  });
  return entries["resources.arsc"] ?? null;
}

function parseResourceTable(bytes: Uint8Array): ParsedTable | null {
  const warnings: string[] = [];
  if (readU16(bytes, 0) !== RES_TABLE_TYPE) {
    return null;
  }
  const tableSize = readU32(bytes, 4);
  const headerSize = readU16(bytes, 2);
  const packageCount = readU32(bytes, 8);
  let cursor = headerSize;
  let tableStringPool: StringPoolChunk | null = null;
  let packageChunk: PackageChunk | null = null;

  while (cursor + 8 <= Math.min(tableSize, bytes.length)) {
    const type = readU16(bytes, cursor);
    const chunkHeaderSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < chunkHeaderSize || cursor + size > bytes.length) {
      return null;
    }
    if (type === RES_STRING_POOL_TYPE && !tableStringPool) {
      tableStringPool = parseStringPool(bytes, cursor, warnings);
    } else if (type === RES_TABLE_PACKAGE_TYPE && !packageChunk) {
      packageChunk = parsePackage(bytes, cursor, warnings);
    }
    cursor += size;
  }

  if (!tableStringPool || !packageChunk) {
    return null;
  }
  return { bytes, headerSize, packageCount, tableStringPool, packageChunk, warnings };
}

function parsePackage(bytes: Uint8Array, offset: number, warnings: string[]): PackageChunk {
  const size = readU32(bytes, offset + 4);
  const headerSize = readU16(bytes, offset + 2);
  const typeStringPoolOffset = readU32(bytes, offset + 268);
  const keyStringPoolOffset = readU32(bytes, offset + 276);
  const typeStringPool = parseStringPool(bytes, offset + typeStringPoolOffset, warnings);
  const keyStringPool = parseStringPool(bytes, offset + keyStringPoolOffset, warnings);
  const children: ChildChunk[] = [];
  let cursor = offset + headerSize;
  while (cursor + 8 <= offset + size) {
    const type = readU16(bytes, cursor);
    const childHeaderSize = readU16(bytes, cursor + 2);
    const childSize = readU32(bytes, cursor + 4);
    if (childSize < childHeaderSize || cursor + childSize > offset + size) {
      warnings.push(`Invalid package child chunk at ${cursor}.`);
      break;
    }
    children.push({ offset: cursor, size: childSize, type });
    cursor += childSize;
  }

  return {
    offset,
    size,
    headerSize,
    id: readU32(bytes, offset + 8),
    name: readUtf16Fixed(bytes, offset + 12, 128),
    typeStringPoolOffset,
    keyStringPoolOffset,
    typeStringPool,
    keyStringPool,
    children
  };
}

function rewriteTypeChunk(
  chunk: Uint8Array,
  splitKeyStrings: string[],
  splitTableStringRemap: number[],
  baseKeyStrings: string[],
  baseKeyIndex: Map<string, number>
): Uint8Array | null {
  const rewritten = new Uint8Array(chunk);
  const headerSize = readU16(rewritten, 2);
  const size = readU32(rewritten, 4);
  const flags = rewritten[9];
  const entryCount = readU32(rewritten, 12);
  const entriesStart = readU32(rewritten, 16);
  const offsetType = flags & 0x03;
  const offsetsStart = headerSize;

  if (size !== rewritten.length) {
    return null;
  }

  if (offsetType === 0x01) {
    const sparseCount = Math.max(0, Math.floor((entriesStart - headerSize) / 4));
    for (let i = 0; i < sparseCount; i++) {
      const entryOffset = readU16(rewritten, offsetsStart + i * 4 + 2);
      if (!rewriteEntry(rewritten, entriesStart + entryOffset * 4, splitKeyStrings, splitTableStringRemap, baseKeyStrings, baseKeyIndex)) {
        return null;
      }
    }
    return rewritten;
  }

  if (offsetType === 0x02) {
    for (let i = 0; i < entryCount; i++) {
      const entryOffset = readU16(rewritten, offsetsStart + i * 2);
      if (entryOffset !== 0xffff && !rewriteEntry(rewritten, entriesStart + entryOffset * 4, splitKeyStrings, splitTableStringRemap, baseKeyStrings, baseKeyIndex)) {
        return null;
      }
    }
    return rewritten;
  }

  for (let i = 0; i < entryCount; i++) {
    const entryOffset = readU32(rewritten, offsetsStart + i * 4);
    if (entryOffset !== 0xffffffff && !rewriteEntry(rewritten, entriesStart + entryOffset, splitKeyStrings, splitTableStringRemap, baseKeyStrings, baseKeyIndex)) {
      return null;
    }
  }
  return rewritten;
}

function rewriteEntry(
  bytes: Uint8Array,
  entryOffset: number,
  splitKeyStrings: string[],
  splitTableStringRemap: number[],
  baseKeyStrings: string[],
  baseKeyIndex: Map<string, number>
): boolean {
  if (entryOffset + 8 > bytes.length) {
    return false;
  }
  const entrySize = readU16(bytes, entryOffset);
  const flags = readU16(bytes, entryOffset + 2);
  const splitKey = splitKeyStrings[readU32(bytes, entryOffset + 4)];
  if (splitKey === undefined) {
    return false;
  }
  writeU32(bytes, entryOffset + 4, getOrAppend(baseKeyStrings, baseKeyIndex, splitKey));

  if ((flags & ENTRY_FLAG_COMPLEX) !== 0) {
    if (entrySize < 16 || entryOffset + entrySize > bytes.length) {
      return false;
    }
    const count = readU32(bytes, entryOffset + entrySize - 4);
    let cursor = entryOffset + entrySize;
    for (let i = 0; i < count; i++) {
      if (cursor + 12 > bytes.length || !rewriteValue(bytes, cursor + 4, splitTableStringRemap)) {
        return false;
      }
      cursor += 12;
    }
    return true;
  }

  return rewriteValue(bytes, entryOffset + entrySize, splitTableStringRemap);
}

function rewriteValue(bytes: Uint8Array, offset: number, splitTableStringRemap: number[]): boolean {
  if (offset + 8 > bytes.length) {
    return false;
  }
  if (bytes[offset + 3] !== TYPE_STRING) {
    return true;
  }
  const mergedIndex = splitTableStringRemap[readU32(bytes, offset + 4)];
  if (mergedIndex === undefined) {
    return false;
  }
  writeU32(bytes, offset + 4, mergedIndex);
  return true;
}

function mergeTypeSpecChunk(baseSpec: Uint8Array | undefined, splitSpec: Uint8Array): Uint8Array {
  if (!baseSpec) {
    return new Uint8Array(splitSpec);
  }
  const baseEntryCount = readU32(baseSpec, 12);
  const splitEntryCount = readU32(splitSpec, 12);
  const entryCount = Math.max(baseEntryCount, splitEntryCount);
  const headerSize = readU16(baseSpec, 2);
  const size = headerSize + entryCount * 4;
  const merged = new Uint8Array(size);
  merged.set(baseSpec.slice(0, headerSize));
  writeU32(merged, 4, size);
  writeU32(merged, 12, entryCount);
  for (let i = 0; i < entryCount; i++) {
    const baseFlags = i < baseEntryCount ? readU32(baseSpec, headerSize + i * 4) : 0;
    const splitFlags = i < splitEntryCount ? readU32(splitSpec, readU16(splitSpec, 2) + i * 4) : 0;
    writeU32(merged, headerSize + i * 4, baseFlags | splitFlags);
  }
  return merged;
}

function rebuildPackage(
  baseBytes: Uint8Array,
  pkg: PackageChunk,
  keyStringPool: Uint8Array,
  typeSpecChunks: Map<number, Uint8Array>,
  remappedBaseTypeChunks: Map<number, Uint8Array>,
  appendedTypeChunks: Uint8Array[]
): Uint8Array {
  const pieces: Uint8Array[] = [];
  const header = new Uint8Array(baseBytes.slice(pkg.offset, pkg.offset + pkg.headerSize));
  pieces.push(header);
  for (const child of pkg.children) {
    if (child.offset === pkg.keyStringPool.offset) {
      pieces.push(keyStringPool);
    } else if (child.type === RES_TABLE_TYPE_SPEC_TYPE) {
      pieces.push(typeSpecChunks.get(baseBytes[child.offset + 8]) ?? baseBytes.slice(child.offset, child.offset + child.size));
    } else if (child.type === RES_TABLE_TYPE_TYPE) {
      pieces.push(remappedBaseTypeChunks.get(child.offset) ?? baseBytes.slice(child.offset, child.offset + child.size));
    } else {
      pieces.push(baseBytes.slice(child.offset, child.offset + child.size));
    }
  }
  pieces.push(...appendedTypeChunks);
  const rebuilt = concat(pieces);
  writeU32(rebuilt, 4, rebuilt.length);
  return rebuilt;
}

function rebuildTable(baseBytes: Uint8Array, base: ParsedTable, tableStringPool: Uint8Array, packageChunk: Uint8Array): Uint8Array {
  const pieces: Uint8Array[] = [baseBytes.slice(0, base.headerSize)];
  let cursor = base.headerSize;
  const tableSize = readU32(baseBytes, 4);
  while (cursor + 8 <= Math.min(tableSize, baseBytes.length)) {
    const type = readU16(baseBytes, cursor);
    const size = readU32(baseBytes, cursor + 4);
    if (cursor === base.tableStringPool.offset) {
      pieces.push(tableStringPool);
    } else if (cursor === base.packageChunk.offset) {
      pieces.push(packageChunk);
    } else {
      pieces.push(baseBytes.slice(cursor, cursor + size));
    }
    cursor += size;
  }
  const rebuilt = concat(pieces);
  writeU32(rebuilt, 4, rebuilt.length);
  return rebuilt;
}

function buildUtf8StringPool(strings: string[], styles: Array<StringPoolStyle | null>): Uint8Array {
  const encodedStrings = strings.map((value) => encodeUtf8PoolString(value));
  const styleCount = lastStyledStringIndex(styles) + 1;
  const encodedStyles = styles.slice(0, styleCount).map(encodeStyle);
  const headerSize = 28;
  const offsetsSize = (strings.length + styleCount) * 4;
  const stringsStart = headerSize + offsetsSize;
  const stringsSize = align4(encodedStrings.reduce((sum, value) => sum + value.length, 0));
  const stylesStart = styleCount > 0 ? stringsStart + stringsSize : 0;
  const stylesSize = styleCount > 0
    ? encodedStyles.reduce((sum, value) => sum + (value?.length ?? 0), 0) + 8
    : 0;
  const size = stringsStart + stringsSize + stylesSize;
  const bytes = new Uint8Array(size);
  writeU16(bytes, 0, RES_STRING_POOL_TYPE);
  writeU16(bytes, 2, headerSize);
  writeU32(bytes, 4, size);
  writeU32(bytes, 8, strings.length);
  writeU32(bytes, 12, styleCount);
  writeU32(bytes, 16, UTF8_FLAG);
  writeU32(bytes, 20, stringsStart);
  writeU32(bytes, 24, stylesStart);
  let cursor = stringsStart;
  for (let i = 0; i < encodedStrings.length; i++) {
    writeU32(bytes, headerSize + i * 4, cursor - stringsStart);
    bytes.set(encodedStrings[i], cursor);
    cursor += encodedStrings[i].length;
  }
  if (styleCount > 0) {
    cursor = stylesStart;
    for (let i = 0; i < styleCount; i++) {
      const encoded = encodedStyles[i];
      writeU32(bytes, headerSize + strings.length * 4 + i * 4, encoded ? cursor - stylesStart : 0xffffffff);
      if (encoded) {
        bytes.set(encoded, cursor);
        cursor += encoded.length;
      }
    }
    bytes.fill(0xff, cursor, cursor + 8);
  }
  return bytes;
}

function encodeStyle(style: StringPoolStyle | null): Uint8Array | null {
  if (!style) {
    return null;
  }
  const bytes = new Uint8Array(style.length * 12 + 4);
  for (let i = 0; i < style.length; i++) {
    writeU32(bytes, i * 12, style[i].nameIndex);
    writeU32(bytes, i * 12 + 4, style[i].firstChar);
    writeU32(bytes, i * 12 + 8, style[i].lastChar);
  }
  writeU32(bytes, style.length * 12, 0xffffffff);
  return bytes;
}

function encodeUtf8PoolString(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  return concat([encodeLength8([...value].length), encodeLength8(encoded.length), encoded, new Uint8Array([0])]);
}

function encodeLength8(value: number): Uint8Array {
  if (value > 0x7f) {
    return new Uint8Array([((value >> 8) & 0x7f) | 0x80, value & 0xff]);
  }
  return new Uint8Array([value]);
}

function parseStringPool(bytes: Uint8Array, offset: number, warnings: string[]): StringPoolChunk {
  const size = readU32(bytes, offset + 4);
  const stringCount = readU32(bytes, offset + 8);
  const styleCount = readU32(bytes, offset + 12);
  const flags = readU32(bytes, offset + 16);
  const stringsStart = readU32(bytes, offset + 20);
  const stylesStart = readU32(bytes, offset + 24);
  const isUtf8 = (flags & UTF8_FLAG) !== 0;
  const offsetsEnd = 28 + (stringCount + styleCount) * 4;
  if (size < 28 || offset + size > bytes.length || stringsStart < offsetsEnd || stringsStart >= size) {
    warnings.push(`Invalid string pool at ${offset}.`);
    return { offset, size, strings: [], styles: [] };
  }
  if (styleCount > stringCount || (styleCount > 0 && (stylesStart < stringsStart || stylesStart >= size))) {
    warnings.push(`Invalid styled string pool at ${offset}.`);
    return { offset, size, strings: [], styles: [] };
  }
  const strings: string[] = [];
  for (let i = 0; i < stringCount; i++) {
    const stringOffset = readU32(bytes, offset + 28 + i * 4);
    const absoluteOffset = offset + stringsStart + stringOffset;
    strings.push(isUtf8 ? readUtf8String(bytes, absoluteOffset, offset + size) : readUtf16String(bytes, absoluteOffset, offset + size));
  }
  const styles: Array<StringPoolStyle | null> = Array.from({ length: stringCount }, () => null);
  for (let i = 0; i < styleCount; i++) {
    const relativeOffset = readU32(bytes, offset + 28 + stringCount * 4 + i * 4);
    if (relativeOffset === 0xffffffff) {
      continue;
    }
    const style = readStyle(bytes, offset + stylesStart + relativeOffset, offset + size, stringCount);
    if (!style) {
      warnings.push(`Invalid style spans for string ${i} in pool at ${offset}.`);
      continue;
    }
    styles[i] = style;
  }
  return { offset, size, strings, styles };
}

function readStyle(bytes: Uint8Array, offset: number, end: number, stringCount: number): StringPoolStyle | null {
  const style: StringPoolStyle = [];
  let cursor = offset;
  while (cursor + 4 <= end) {
    const nameIndex = readU32(bytes, cursor);
    if (nameIndex === 0xffffffff) {
      return style;
    }
    if (cursor + 12 > end || nameIndex >= stringCount) {
      return null;
    }
    style.push({ nameIndex, firstChar: readU32(bytes, cursor + 4), lastChar: readU32(bytes, cursor + 8) });
    cursor += 12;
  }
  return null;
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

function cloneStyle(style: StringPoolStyle | null): StringPoolStyle | null {
  return style?.map((span) => ({ ...span })) ?? null;
}

function normalizeStyledStringPool(
  strings: string[],
  styles: Array<StringPoolStyle | null>
): { strings: string[]; styles: Array<StringPoolStyle | null>; remap: number[] } {
  const order = strings.map((_value, index) => index).sort((left, right) => Number(!styles[left]) - Number(!styles[right]));
  const remap = new Array<number>(strings.length);
  order.forEach((oldIndex, newIndex) => {
    remap[oldIndex] = newIndex;
  });
  return {
    strings: order.map((index) => strings[index]),
    styles: order.map((index) => styles[index]?.map((span) => ({ ...span, nameIndex: remap[span.nameIndex] })) ?? null),
    remap
  };
}

function remapTypeChunkStringValues(chunk: Uint8Array, tableStringRemap: number[]): Uint8Array | null {
  const remapped = new Uint8Array(chunk);
  const headerSize = readU16(remapped, 2);
  const size = readU32(remapped, 4);
  const flags = remapped[9];
  const entryCount = readU32(remapped, 12);
  const entriesStart = readU32(remapped, 16);
  const offsetType = flags & 0x03;
  if (size !== remapped.length) {
    return null;
  }
  if (offsetType === 0x01) {
    const sparseCount = Math.max(0, Math.floor((entriesStart - headerSize) / 4));
    for (let i = 0; i < sparseCount; i++) {
      if (!remapEntryStringValues(remapped, entriesStart + readU16(remapped, headerSize + i * 4 + 2) * 4, tableStringRemap)) {
        return null;
      }
    }
    return remapped;
  }
  if (offsetType === 0x02) {
    for (let i = 0; i < entryCount; i++) {
      const entryOffset = readU16(remapped, headerSize + i * 2);
      if (entryOffset !== 0xffff && !remapEntryStringValues(remapped, entriesStart + entryOffset * 4, tableStringRemap)) {
        return null;
      }
    }
    return remapped;
  }
  for (let i = 0; i < entryCount; i++) {
    const entryOffset = readU32(remapped, headerSize + i * 4);
    if (entryOffset !== 0xffffffff && !remapEntryStringValues(remapped, entriesStart + entryOffset, tableStringRemap)) {
      return null;
    }
  }
  return remapped;
}

function remapEntryStringValues(bytes: Uint8Array, entryOffset: number, tableStringRemap: number[]): boolean {
  if (entryOffset + 8 > bytes.length) {
    return false;
  }
  const entrySize = readU16(bytes, entryOffset);
  const flags = readU16(bytes, entryOffset + 2);
  if ((flags & ENTRY_FLAG_COMPLEX) !== 0) {
    if (entrySize < 16 || entryOffset + entrySize > bytes.length) {
      return false;
    }
    const count = readU32(bytes, entryOffset + entrySize - 4);
    let cursor = entryOffset + entrySize;
    for (let i = 0; i < count; i++) {
      if (cursor + 12 > bytes.length || !rewriteValue(bytes, cursor + 4, tableStringRemap)) {
        return false;
      }
      cursor += 12;
    }
    return true;
  }
  return rewriteValue(bytes, entryOffset + entrySize, tableStringRemap);
}

function styledStringKey(pool: StringPoolChunk, index: number): string {
  const style = pool.styles[index];
  if (!style) {
    return JSON.stringify([pool.strings[index], null]);
  }
  return JSON.stringify([
    pool.strings[index],
    style.map((span) => [pool.strings[span.nameIndex], span.firstChar, span.lastChar])
  ]);
}

function indexStyledStrings(pool: StringPoolChunk): Map<string, number> {
  const map = new Map<string, number>();
  pool.strings.forEach((_value, index) => {
    const key = styledStringKey(pool, index);
    if (!map.has(key)) {
      map.set(key, index);
    }
  });
  return map;
}

function mergeStyledStringPool(
  split: StringPoolChunk,
  mergedStrings: string[],
  mergedStyles: Array<StringPoolStyle | null>,
  mergedIndex: Map<string, number>
): number[] {
  const remap = new Array<number>(split.strings.length);
  const appended: number[] = [];
  for (let i = 0; i < split.strings.length; i++) {
    const key = styledStringKey(split, i);
    const existing = mergedIndex.get(key);
    if (existing !== undefined) {
      remap[i] = existing;
      continue;
    }
    const next = mergedStrings.length;
    remap[i] = next;
    appended.push(i);
    mergedStrings.push(split.strings[i]);
    mergedStyles.push(null);
    mergedIndex.set(key, next);
  }
  for (const splitIndex of appended) {
    const style = split.styles[splitIndex];
    if (style) {
      mergedStyles[remap[splitIndex]] = style.map((span) => ({
        ...span,
        nameIndex: remap[span.nameIndex]
      }));
    }
  }
  return remap;
}

function lastStyledStringIndex(styles: Array<StringPoolStyle | null>): number {
  for (let i = styles.length - 1; i >= 0; i--) {
    if (styles[i]) {
      return i;
    }
  }
  return -1;
}

function indexStrings(strings: string[]): Map<string, number> {
  const map = new Map<string, number>();
  strings.forEach((value, index) => {
    if (!map.has(value)) {
      map.set(value, index);
    }
  });
  return map;
}

function getOrAppend(strings: string[], index: Map<string, number>, value: string): number {
  const existing = index.get(value);
  if (existing !== undefined) {
    return existing;
  }
  const next = strings.length;
  strings.push(value);
  index.set(value, next);
  return next;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
}

function align4(value: number): number {
  return (value + 3) & ~3;
}

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function writeU16(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeU32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

type StringPool = {
  strings: string[];
};

type SanitizeResult = {
  bytes: Uint8Array;
  removedAttributes: string[];
  removedElements: string[];
  remainingSplitElements: string[];
  beforeMarkers: string[];
  afterMarkers: string[];
};

const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;

const KNOWN_SPLIT_ATTRIBUTE_NAMES = new Set([
  "requiredSplitTypes",
  "splitTypes",
  "isSplitRequired"
]);

const KNOWN_SPLIT_ATTRIBUTE_IDS = new Set([
  0x01010591,
  0x01010592,
  0x01010598
]);

const SPLIT_MARKERS = [
  "requiredSplitTypes",
  "splitTypes",
  "isSplitRequired",
  "uses-split",
  "com.android.vending.splits.required",
  "com.android.vending.splits"
];

const SPLIT_META_DATA_NAMES = new Set([
  "com.android.vending.splits.required",
  "com.android.vending.splits"
]);

const SPLIT_ELEMENT_NAMES = new Set([
  "uses-split"
]);

export function sanitizeBinaryManifest(input: Uint8Array): SanitizeResult {
  const beforeMarkers = findUtf16Markers(input, SPLIT_MARKERS);
  const pool = readStringPool(input);
  if (!pool) {
    return {
      bytes: input,
      removedAttributes: [],
      removedElements: [],
      remainingSplitElements: [],
      beforeMarkers,
      afterMarkers: beforeMarkers
    };
  }

  const output = new Uint8Array(input);
  const removedAttributes: string[] = [];
  let changedSize = 0;
  let cursor = 8;

  while (cursor + 8 <= output.length - changedSize) {
    const type = readU16(output, cursor);
    const size = readU32(output, cursor + 4);
    if (size < 8) {
      break;
    }

    if (type === RES_XML_START_ELEMENT_TYPE) {
      const chunkEnd = cursor + size;
      const extensionStart = cursor + 16;
      const attrStart = extensionStart + readU16(output, extensionStart + 8);
      const attrSize = readU16(output, extensionStart + 10);
      const attrCountOffset = extensionStart + 12;
      let attrCount = readU16(output, attrCountOffset);
      let attrIndex = 0;

      while (attrIndex < attrCount) {
        const attrOffset = attrStart + attrIndex * attrSize;
        if (attrOffset + attrSize > chunkEnd) {
          break;
        }

        const nameIndex = readU32(output, attrOffset + 4);
        const data = readU32(output, attrOffset + 16);
        const name = pool.strings[nameIndex] ?? "";
        const shouldRemove = KNOWN_SPLIT_ATTRIBUTE_NAMES.has(name) || KNOWN_SPLIT_ATTRIBUTE_IDS.has(data);

        if (!shouldRemove) {
          attrIndex++;
          continue;
        }

        removedAttributes.push(name || `resource:0x${data.toString(16)}`);
        output.copyWithin(attrOffset, attrOffset + attrSize, output.length - changedSize);
        changedSize += attrSize;
        attrCount--;
        writeU16(output, attrCountOffset, attrCount);
        writeU32(output, cursor + 4, readU32(output, cursor + 4) - attrSize);
        decrementXmlSize(output, attrSize);
        continue;
      }
    }

    const adjustedSize = readU32(output, cursor + 4);
    cursor += adjustedSize;
  }

  let bytes = changedSize === 0 ? input : output.slice(0, output.length - changedSize);
  const elementResult = removeSplitMetaDataElements(bytes, pool);
  bytes = elementResult.bytes;

  return {
    bytes,
    removedAttributes,
    removedElements: elementResult.removedElements,
    remainingSplitElements: elementResult.remainingSplitElements,
    beforeMarkers,
    afterMarkers: findUtf16Markers(bytes, SPLIT_MARKERS)
  };
}

export function readBinaryManifestPackageName(input: Uint8Array): string | null {
  const pool = readStringPool(input);
  if (!pool) {
    return null;
  }

  let cursor = 8;
  while (cursor + 8 <= input.length) {
    const type = readU16(input, cursor);
    const size = readU32(input, cursor + 4);
    if (size < 8 || cursor + size > input.length) {
      return null;
    }

    if (type === RES_XML_START_ELEMENT_TYPE && getStartElementName(input, cursor, pool) === "manifest") {
      return getAttributeStringValue(input, cursor, pool, "package");
    }

    cursor += size;
  }
  return null;
}

export function readBinaryManifestMinSdk(input: Uint8Array): number | null {
  const pool = readStringPool(input);
  if (!pool) {
    return null;
  }

  let cursor = 8;
  while (cursor + 8 <= input.length) {
    const type = readU16(input, cursor);
    const size = readU32(input, cursor + 4);
    if (size < 8 || cursor + size > input.length) {
      return null;
    }

    if (type === RES_XML_START_ELEMENT_TYPE && getStartElementName(input, cursor, pool) === "uses-sdk") {
      return getAttributeIntegerValue(input, cursor, pool, "minSdkVersion");
    }

    cursor += size;
  }
  return null;
}

export function readBinaryManifestTargetSdk(input: Uint8Array): number | null {
  const pool = readStringPool(input);
  if (!pool) {
    return null;
  }

  let cursor = 8;
  while (cursor + 8 <= input.length) {
    const type = readU16(input, cursor);
    const size = readU32(input, cursor + 4);
    if (size < 8 || cursor + size > input.length) {
      return null;
    }

    if (type === RES_XML_START_ELEMENT_TYPE && getStartElementName(input, cursor, pool) === "uses-sdk") {
      return getAttributeIntegerValue(input, cursor, pool, "targetSdkVersion");
    }

    cursor += size;
  }
  return null;
}

export function findUtf16Markers(bytes: Uint8Array, markers: string[]): string[] {
  return markers.filter((marker) => includesAscii(bytes, marker) || includesUtf16Le(bytes, marker));
}

function readStringPool(bytes: Uint8Array): StringPool | null {
  let cursor = 8;
  while (cursor + 28 <= bytes.length) {
    const type = readU16(bytes, cursor);
    const headerSize = readU16(bytes, cursor + 2);
    const size = readU32(bytes, cursor + 4);
    if (size < headerSize || cursor + size > bytes.length) {
      return null;
    }
    if (type !== RES_STRING_POOL_TYPE) {
      cursor += size;
      continue;
    }

    const stringCount = readU32(bytes, cursor + 8);
    const flags = readU32(bytes, cursor + 16);
    const stringsStart = readU32(bytes, cursor + 20);
    const isUtf8 = (flags & 0x00000100) !== 0;
    const strings: string[] = [];

    for (let i = 0; i < stringCount; i++) {
      const offset = readU32(bytes, cursor + headerSize + i * 4);
      const stringOffset = cursor + stringsStart + offset;
      strings.push(isUtf8 ? readUtf8String(bytes, stringOffset) : readUtf16String(bytes, stringOffset));
    }

    return { strings };
  }
  return null;
}

function removeSplitMetaDataElements(input: Uint8Array, pool: StringPool): {
  bytes: Uint8Array;
  removedElements: string[];
  remainingSplitElements: string[];
} {
  const rangesToRemove: Array<{ start: number; end: number; name: string }> = [];
  const remainingSplitElements: string[] = [];
  let cursor = 8;

  while (cursor + 8 <= input.length) {
    const type = readU16(input, cursor);
    const size = readU32(input, cursor + 4);
    if (size < 8 || cursor + size > input.length) {
      break;
    }

    if (type === RES_XML_START_ELEMENT_TYPE) {
      const elementName = getStartElementName(input, cursor, pool);
      if (elementName && SPLIT_ELEMENT_NAMES.has(elementName)) {
        const splitName = getAttributeStringValue(input, cursor, pool, "name") ?? elementName;
        const end = findMatchingEndElement(input, cursor, pool, elementName);
        if (end > cursor) {
          rangesToRemove.push({ start: cursor, end, name: `uses-split:${splitName}` });
        } else {
          remainingSplitElements.push(`uses-split:${splitName}`);
        }
      } else if (elementName === "meta-data") {
        const metaName = getAttributeStringValue(input, cursor, pool, "name");
        if (metaName && SPLIT_META_DATA_NAMES.has(metaName)) {
          const end = findMatchingEndElement(input, cursor, pool, elementName);
          if (end > cursor) {
            rangesToRemove.push({ start: cursor, end, name: metaName });
          } else {
            remainingSplitElements.push(metaName);
          }
        }
      }
    }

    cursor += size;
  }

  if (rangesToRemove.length === 0) {
    return { bytes: input, removedElements: [], remainingSplitElements };
  }

  const sorted = rangesToRemove.sort((a, b) => a.start - b.start);
  const removedBytes = sorted.reduce((sum, range) => sum + range.end - range.start, 0);
  const output = new Uint8Array(input.length - removedBytes);
  let readOffset = 0;
  let writeOffset = 0;

  for (const range of sorted) {
    output.set(input.slice(readOffset, range.start), writeOffset);
    writeOffset += range.start - readOffset;
    readOffset = range.end;
  }
  output.set(input.slice(readOffset), writeOffset);
  decrementXmlSize(output, removedBytes);

  const removedElements = sorted.map((range) => range.name);
  const removedSet = new Set(removedElements);
  const remainingAfterRemoval = listSplitMetaDataElements(output, pool).filter((name) => !removedSet.has(name));
  return {
    bytes: output,
    removedElements,
    remainingSplitElements: [...remainingSplitElements, ...remainingAfterRemoval]
  };
}

function listSplitMetaDataElements(bytes: Uint8Array, pool: StringPool): string[] {
  const result: string[] = [];
  let cursor = 8;
  while (cursor + 8 <= bytes.length) {
    const type = readU16(bytes, cursor);
    const size = readU32(bytes, cursor + 4);
    if (size < 8 || cursor + size > bytes.length) {
      break;
    }
    if (type === RES_XML_START_ELEMENT_TYPE) {
      const elementName = getStartElementName(bytes, cursor, pool);
      if (elementName && SPLIT_ELEMENT_NAMES.has(elementName)) {
        result.push(`uses-split:${getAttributeStringValue(bytes, cursor, pool, "name") ?? elementName}`);
      } else if (elementName === "meta-data") {
        const metaName = getAttributeStringValue(bytes, cursor, pool, "name");
        if (metaName && SPLIT_META_DATA_NAMES.has(metaName)) {
          result.push(metaName);
        }
      }
    }
    cursor += size;
  }
  return result;
}

function findMatchingEndElement(bytes: Uint8Array, startOffset: number, pool: StringPool, startName: string): number {
  let cursor = startOffset + readU32(bytes, startOffset + 4);
  let depth = 1;

  while (cursor + 8 <= bytes.length) {
    const type = readU16(bytes, cursor);
    const size = readU32(bytes, cursor + 4);
    if (size < 8 || cursor + size > bytes.length) {
      return -1;
    }

    if (type === RES_XML_START_ELEMENT_TYPE) {
      depth++;
    } else if (type === RES_XML_END_ELEMENT_TYPE) {
      depth--;
      const endName = getEndElementName(bytes, cursor, pool);
      if (depth === 0 && endName === startName) {
        return cursor + size;
      }
    }
    cursor += size;
  }

  return -1;
}

function getStartElementName(bytes: Uint8Array, offset: number, pool: StringPool): string | null {
  const nameIndex = readU32(bytes, offset + 20);
  return pool.strings[nameIndex] ?? null;
}

function getEndElementName(bytes: Uint8Array, offset: number, pool: StringPool): string | null {
  const nameIndex = readU32(bytes, offset + 20);
  return pool.strings[nameIndex] ?? null;
}

function getAttributeStringValue(bytes: Uint8Array, elementOffset: number, pool: StringPool, targetName: string): string | null {
  const extensionStart = elementOffset + 16;
  const attrStart = extensionStart + readU16(bytes, extensionStart + 8);
  const attrSize = readU16(bytes, extensionStart + 10);
  const attrCount = readU16(bytes, extensionStart + 12);
  const chunkEnd = elementOffset + readU32(bytes, elementOffset + 4);

  for (let i = 0; i < attrCount; i++) {
    const attrOffset = attrStart + i * attrSize;
    if (attrOffset + attrSize > chunkEnd) {
      return null;
    }
    const nameIndex = readU32(bytes, attrOffset + 4);
    if (pool.strings[nameIndex] !== targetName) {
      continue;
    }
    const rawValue = readU32(bytes, attrOffset + 8);
    if (rawValue !== 0xffffffff && pool.strings[rawValue]) {
      return pool.strings[rawValue];
    }
    const valueType = bytes[attrOffset + 15];
    const data = readU32(bytes, attrOffset + 16);
    if (valueType === 0x03 && pool.strings[data]) {
      return pool.strings[data];
    }
  }
  return null;
}

function getAttributeIntegerValue(bytes: Uint8Array, elementOffset: number, pool: StringPool, targetName: string): number | null {
  const value = getAttributeValue(bytes, elementOffset, pool, targetName);
  if (!value) {
    return null;
  }
  if (value.rawValue !== 0xffffffff) {
    const parsed = Number.parseInt(pool.strings[value.rawValue] ?? "", 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (value.valueType >= 0x10 && value.valueType <= 0x1f) {
    return value.data;
  }
  if (value.valueType === 0x03) {
    const parsed = Number.parseInt(pool.strings[value.data] ?? "", 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function getAttributeValue(
  bytes: Uint8Array,
  elementOffset: number,
  pool: StringPool,
  targetName: string
): { rawValue: number; valueType: number; data: number } | null {
  const extensionStart = elementOffset + 16;
  const attrStart = extensionStart + readU16(bytes, extensionStart + 8);
  const attrSize = readU16(bytes, extensionStart + 10);
  const attrCount = readU16(bytes, extensionStart + 12);
  const chunkEnd = elementOffset + readU32(bytes, elementOffset + 4);

  for (let i = 0; i < attrCount; i++) {
    const attrOffset = attrStart + i * attrSize;
    if (attrOffset + attrSize > chunkEnd) {
      return null;
    }
    const nameIndex = readU32(bytes, attrOffset + 4);
    if (pool.strings[nameIndex] !== targetName) {
      continue;
    }
    return {
      rawValue: readU32(bytes, attrOffset + 8),
      valueType: bytes[attrOffset + 15],
      data: readU32(bytes, attrOffset + 16)
    };
  }
  return null;
}

function readUtf8String(bytes: Uint8Array, offset: number): string {
  const [_, afterUtf16Length] = readLength8(bytes, offset);
  const [byteLength, dataOffset] = readLength8(bytes, afterUtf16Length);
  return new TextDecoder().decode(bytes.slice(dataOffset, dataOffset + byteLength));
}

function readUtf16String(bytes: Uint8Array, offset: number): string {
  const [length, dataOffset] = readLength16(bytes, offset);
  const chars: number[] = [];
  for (let i = 0; i < length; i++) {
    chars.push(readU16(bytes, dataOffset + i * 2));
  }
  return String.fromCharCode(...chars);
}

function readLength8(bytes: Uint8Array, offset: number): [number, number] {
  const first = bytes[offset];
  if ((first & 0x80) === 0) {
    return [first, offset + 1];
  }
  return [((first & 0x7f) << 8) | bytes[offset + 1], offset + 2];
}

function readLength16(bytes: Uint8Array, offset: number): [number, number] {
  const first = readU16(bytes, offset);
  if ((first & 0x8000) === 0) {
    return [first, offset + 2];
  }
  return [((first & 0x7fff) << 16) | readU16(bytes, offset + 2), offset + 4];
}

function includesAscii(bytes: Uint8Array, value: string): boolean {
  return indexOfBytes(bytes, new TextEncoder().encode(value)) !== -1;
}

function includesUtf16Le(bytes: Uint8Array, value: string): boolean {
  const needle = new Uint8Array(value.length * 2);
  for (let i = 0; i < value.length; i++) {
    needle[i * 2] = value.charCodeAt(i) & 0xff;
    needle[i * 2 + 1] = value.charCodeAt(i) >> 8;
  }
  return indexOfBytes(bytes, needle) !== -1;
}

function indexOfBytes(bytes: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= bytes.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (bytes[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

function decrementXmlSize(bytes: Uint8Array, amount: number) {
  const size = readU32(bytes, 4);
  writeU32(bytes, 4, size - amount);
}

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function writeU16(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >> 8) & 0xff;
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function writeU32(bytes: Uint8Array, offset: number, value: number) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >> 8) & 0xff;
  bytes[offset + 2] = (value >> 16) & 0xff;
  bytes[offset + 3] = (value >> 24) & 0xff;
}

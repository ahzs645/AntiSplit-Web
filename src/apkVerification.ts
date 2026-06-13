export type ZipEntryInfo = {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  dataOffset: number;
};

type ApkVerification = {
  passed: string[];
  warnings: string[];
};

export type ApkSigningBlockInfo = {
  present: boolean;
  offset?: number;
  size?: number;
  pairs: Array<{
    id: number;
    idHex: string;
    name: string;
    size: number;
  }>;
  warnings: string[];
};

const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const EOCD_SIGNATURE = 0x06054b50;
const BINARY_XML_SIGNATURE = 0x00080003;
const APK_SIGNATURE_RE = /^META-INF\/(?:[^/]+\.(?:RSA|DSA|EC|SF)|MANIFEST\.MF)$/i;
const APK_SIG_BLOCK_MAGIC = new Uint8Array([
  0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
  0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
]);
const APK_SIGNATURE_SCHEME_IDS: Record<number, string> = {
  0x7109871a: "APK Signature Scheme v2",
  0xf05368c0: "APK Signature Scheme v3",
  0x1b93ad61: "APK Signature Scheme v3.1",
  0x6dff800d: "APK Source Stamp"
};

export function verifyMergedApk(bytes: Uint8Array): ApkVerification {
  const entries = readCentralDirectory(bytes);
  const passed: string[] = [];
  const warnings: string[] = [];
  const names = new Set(entries.map((entry) => entry.name));

  if (names.has("AndroidManifest.xml")) {
    passed.push("APK contains AndroidManifest.xml.");
  } else {
    warnings.push("APK is missing AndroidManifest.xml.");
  }

  if ([...names].some((name) => /^classes\d*\.dex$/.test(name))) {
    passed.push("APK contains at least one DEX file.");
  } else {
    warnings.push("APK does not contain a DEX file.");
  }

  const signatureEntries = entries.filter((entry) => APK_SIGNATURE_RE.test(entry.name));
  const generatedSignatureEntries = new Set(["META-INF/MANIFEST.MF", "META-INF/ANTISPLT.SF", "META-INF/ANTISPLT.RSA"]);
  const staleSignatureEntries = signatureEntries.filter((entry) => !generatedSignatureEntries.has(entry.name));
  if (names.has("META-INF/ANTISPLT.SF") && names.has("META-INF/ANTISPLT.RSA")) {
    passed.push("APK contains AntiSplit Web JAR/v1 signature files.");
  }
  if (staleSignatureEntries.length === 0) {
    passed.push("Pre-existing JAR signature files were removed from META-INF.");
  } else {
    warnings.push(`APK still contains ${staleSignatureEntries.length} pre-existing JAR signature file(s).`);
  }

  const nativeLibs = entries.filter((entry) => /^lib\/[^/]+\/[^/]+\.so$/.test(entry.name));
  const compressedNativeLibs = nativeLibs.filter((entry) => entry.method !== 0);
  const unalignedNativeLibs = nativeLibs.filter((entry) => entry.dataOffset % 4096 !== 0);
  if (nativeLibs.length > 0 && compressedNativeLibs.length === 0) {
    passed.push(`All ${nativeLibs.length} native library entr${nativeLibs.length === 1 ? "y is" : "ies are"} stored uncompressed.`);
  } else if (compressedNativeLibs.length > 0) {
    warnings.push(`${compressedNativeLibs.length} native library entr${compressedNativeLibs.length === 1 ? "y is" : "ies are"} compressed.`);
  }
  if (nativeLibs.length > 0 && unalignedNativeLibs.length === 0) {
    passed.push(`All ${nativeLibs.length} native library entr${nativeLibs.length === 1 ? "y is" : "ies are"} 4096-byte aligned.`);
  } else if (unalignedNativeLibs.length > 0) {
    warnings.push(`${unalignedNativeLibs.length} native library entr${unalignedNativeLibs.length === 1 ? "y is" : "ies are"} not 4096-byte aligned.`);
  }

  const manifest = extractStoredOrDeflatedEntry(bytes, entries.find((entry) => entry.name === "AndroidManifest.xml"));
  if (manifest && hasBinaryXmlHeader(manifest)) {
    passed.push("AndroidManifest.xml has a binary XML header.");
  } else if (manifest) {
    warnings.push("AndroidManifest.xml does not look like Android binary XML.");
  }

  const signingBlock = inspectApkSigningBlock(bytes);
  if (signingBlock.present) {
    const schemeNames = signingBlock.pairs.map((pair) => pair.name).join(", ");
    passed.push(`APK Signing Block is present${schemeNames ? ` (${schemeNames})` : ""}.`);
    warnings.push(...signingBlock.warnings);
  } else {
    passed.push("No APK Signing Block detected; output relies on JAR/v1 signing.");
  }

  return { passed, warnings };
}

export function inspectApkSigningBlock(bytes: Uint8Array): ApkSigningBlockInfo {
  const eocd = findEocd(bytes);
  if (eocd === -1) {
    return { present: false, pairs: [], warnings: ["Could not find ZIP end-of-central-directory record."] };
  }

  const centralDirectoryOffset = readU32(bytes, eocd + 16);
  if (centralDirectoryOffset < 32) {
    return { present: false, pairs: [], warnings: [] };
  }

  const footerOffset = centralDirectoryOffset - 24;
  if (footerOffset < 0 || !bytesEqual(bytes.slice(footerOffset + 8, footerOffset + 24), APK_SIG_BLOCK_MAGIC)) {
    return { present: false, pairs: [], warnings: [] };
  }

  const sizeInFooter = readU64Safe(bytes, footerOffset);
  if (sizeInFooter < 24 || sizeInFooter > Number.MAX_SAFE_INTEGER) {
    return { present: false, pairs: [], warnings: [`APK Signing Block size is out of range: ${sizeInFooter}.`] };
  }

  const blockOffset = centralDirectoryOffset - Number(sizeInFooter) - 8;
  if (blockOffset < 0 || blockOffset + 8 > bytes.length) {
    return { present: false, pairs: [], warnings: [`APK Signing Block offset is out of range: ${blockOffset}.`] };
  }

  const sizeInHeader = readU64Safe(bytes, blockOffset);
  const warnings: string[] = [];
  if (sizeInHeader !== sizeInFooter) {
    warnings.push("APK Signing Block header/footer sizes do not match.");
  }

  const pairs: ApkSigningBlockInfo["pairs"] = [];
  let cursor = blockOffset + 8;
  const pairsEnd = centralDirectoryOffset - 24;
  while (cursor + 12 <= pairsEnd) {
    const pairSize = readU64Safe(bytes, cursor);
    if (pairSize < 4 || pairSize > Number.MAX_SAFE_INTEGER || cursor + 8 + Number(pairSize) > pairsEnd) {
      warnings.push(`Invalid APK Signing Block pair at offset ${cursor}.`);
      break;
    }
    const id = readU32(bytes, cursor + 8);
    pairs.push({
      id,
      idHex: `0x${id.toString(16).padStart(8, "0")}`,
      name: APK_SIGNATURE_SCHEME_IDS[id] ?? `Unknown ${id.toString(16).padStart(8, "0")}`,
      size: Number(pairSize) - 4
    });
    cursor += 8 + Number(pairSize);
  }

  return {
    present: true,
    offset: blockOffset,
    size: centralDirectoryOffset - blockOffset,
    pairs,
    warnings
  };
}

export function readCentralDirectory(bytes: Uint8Array): ZipEntryInfo[] {
  const eocd = findEocd(bytes);
  if (eocd === -1) {
    throw new Error("Could not find ZIP end-of-central-directory record.");
  }

  const entryCount = readU16(bytes, eocd + 10);
  const centralDirectoryOffset = readU32(bytes, eocd + 16);
  const entries: ZipEntryInfo[] = [];
  let cursor = centralDirectoryOffset;

  for (let i = 0; i < entryCount; i++) {
    if (readU32(bytes, cursor) !== CENTRAL_DIRECTORY_SIGNATURE) {
      throw new Error(`Invalid ZIP central-directory signature at offset ${cursor}.`);
    }

    const method = readU16(bytes, cursor + 10);
    const compressedSize = readU32(bytes, cursor + 20);
    const uncompressedSize = readU32(bytes, cursor + 24);
    const nameLength = readU16(bytes, cursor + 28);
    const extraLength = readU16(bytes, cursor + 30);
    const commentLength = readU16(bytes, cursor + 32);
    const localHeaderOffset = readU32(bytes, cursor + 42);
    const name = new TextDecoder().decode(bytes.slice(cursor + 46, cursor + 46 + nameLength));
    const localNameLength = readU16(bytes, localHeaderOffset + 26);
    const localExtraLength = readU16(bytes, localHeaderOffset + 28);
    const dataOffset = localHeaderOffset + 30 + localNameLength + localExtraLength;

    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset, dataOffset });
    cursor += 46 + nameLength + extraLength + commentLength;
  }

  return entries;
}

function extractStoredOrDeflatedEntry(bytes: Uint8Array, entry?: ZipEntryInfo): Uint8Array | null {
  if (!entry) {
    return null;
  }
  if (entry.method !== 0) {
    return null;
  }

  if (readU32(bytes, entry.localHeaderOffset) !== 0x04034b50) {
    return null;
  }
  const nameLength = readU16(bytes, entry.localHeaderOffset + 26);
  const extraLength = readU16(bytes, entry.localHeaderOffset + 28);
  const dataOffset = entry.localHeaderOffset + 30 + nameLength + extraLength;
  return bytes.slice(dataOffset, dataOffset + entry.uncompressedSize);
}

function hasBinaryXmlHeader(bytes: Uint8Array): boolean {
  return bytes.length >= 8 && readU32(bytes, 0) === BINARY_XML_SIGNATURE && readU32(bytes, 4) <= bytes.length;
}

function findEocd(bytes: Uint8Array): number {
  const minOffset = Math.max(0, bytes.length - 22 - 0xffff);
  for (let i = bytes.length - 22; i >= minOffset; i--) {
    if (readU32(bytes, i) === EOCD_SIGNATURE) {
      return i;
    }
  }
  return -1;
}

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function readU64Safe(bytes: Uint8Array, offset: number): number {
  const low = readU32(bytes, offset);
  const high = readU32(bytes, offset + 4);
  return high * 0x100000000 + low;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

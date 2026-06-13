import forge from "node-forge";
import { getDebugSigningIdentity } from "./apkV1Signer";

type ZipSections = {
  eocdOffset: number;
  centralDirectoryOffset: number;
};

type V2SignResult = {
  apkBytes: Uint8Array;
  signingBlockSize: number;
};

const EOCD_SIGNATURE = 0x06054b50;
const APK_V2_BLOCK_ID = 0x7109871a;
const APK_V3_BLOCK_ID = 0xf05368c0;
const RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103;
const CHUNK_SIZE = 1024 * 1024;
const V3_MIN_SDK_VERSION = 28;
const V3_MAX_SDK_VERSION = 0x7fffffff;
const APK_SIG_BLOCK_MAGIC = new Uint8Array([
  0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
  0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
]);

export function signApkWithV2DebugKey(inputApk: Uint8Array): V2SignResult {
  return signApkWithDebugKeySigningPairs(inputApk, ["v2"]);
}

export function signApkWithV2V3DebugKey(inputApk: Uint8Array): V2SignResult {
  return signApkWithDebugKeySigningPairs(inputApk, ["v2", "v3"]);
}

function signApkWithDebugKeySigningPairs(inputApk: Uint8Array, schemes: Array<"v2" | "v3">): V2SignResult {
  const sections = findZipSections(inputApk);
  const beforeCentralDirectory = inputApk.slice(0, sections.centralDirectoryOffset);
  const centralDirectory = inputApk.slice(sections.centralDirectoryOffset, sections.eocdOffset);
  const eocdForDigest = new Uint8Array(inputApk.slice(sections.eocdOffset));
  writeU32(eocdForDigest, 16, sections.centralDirectoryOffset);

  const contentDigest = computeV2ChunkedSha256Digest([beforeCentralDirectory, centralDirectory, eocdForDigest]);
  const pairs: Array<[number, Uint8Array]> = [];
  if (schemes.includes("v2")) {
    pairs.push([APK_V2_BLOCK_ID, buildV2SignatureSchemeBlock(contentDigest)]);
  }
  if (schemes.includes("v3")) {
    pairs.push([APK_V3_BLOCK_ID, buildV3SignatureSchemeBlock(contentDigest)]);
  }
  const signingBlock = buildApkSigningBlock(pairs);
  const eocd = new Uint8Array(inputApk.slice(sections.eocdOffset));
  writeU32(eocd, 16, sections.centralDirectoryOffset + signingBlock.length);

  return {
    apkBytes: concat([
      beforeCentralDirectory,
      signingBlock,
      centralDirectory,
      eocd
    ]),
    signingBlockSize: signingBlock.length
  };
}

function buildV2SignatureSchemeBlock(contentDigest: Uint8Array): Uint8Array {
  const identity = getDebugSigningIdentity();
  const digestRecord = encodeLengthPrefixedPairsOfIntAndLengthPrefixedBytes([
    [RSA_PKCS1_V1_5_WITH_SHA256, contentDigest]
  ]);
  const certificateRecord = encodeSequenceOfLengthPrefixedElements([identity.certificateDer]);
  const signedData = encodeSequenceOfLengthPrefixedElements([
    digestRecord,
    certificateRecord,
    new Uint8Array(0),
    new Uint8Array(0)
  ]);
  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(signedData), "raw");
  const signature = binaryToUint8(identity.privateKey.sign(md));
  const signatures = encodeLengthPrefixedPairsOfIntAndLengthPrefixedBytes([
    [RSA_PKCS1_V1_5_WITH_SHA256, signature]
  ]);
  const signerBlock = encodeSequenceOfLengthPrefixedElements([
    signedData,
    signatures,
    identity.publicKeyDer
  ]);
  const signers = encodeSequenceOfLengthPrefixedElements([signerBlock]);
  return encodeSequenceOfLengthPrefixedElements([signers]);
}

function buildV3SignatureSchemeBlock(contentDigest: Uint8Array): Uint8Array {
  const identity = getDebugSigningIdentity();
  const digestRecord = encodeLengthPrefixedPairsOfIntAndLengthPrefixedBytes([
    [RSA_PKCS1_V1_5_WITH_SHA256, contentDigest]
  ]);
  const certificateRecord = encodeSequenceOfLengthPrefixedElements([identity.certificateDer]);
  const signedData = concat([
    uint32Le(digestRecord.length),
    digestRecord,
    uint32Le(certificateRecord.length),
    certificateRecord,
    uint32Le(V3_MIN_SDK_VERSION),
    uint32Le(V3_MAX_SDK_VERSION),
    uint32Le(0)
  ]);
  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(signedData), "raw");
  const signature = binaryToUint8(identity.privateKey.sign(md));
  const signatures = encodeLengthPrefixedPairsOfIntAndLengthPrefixedBytes([
    [RSA_PKCS1_V1_5_WITH_SHA256, signature]
  ]);
  const signerBlock = concat([
    uint32Le(signedData.length),
    signedData,
    uint32Le(V3_MIN_SDK_VERSION),
    uint32Le(V3_MAX_SDK_VERSION),
    uint32Le(signatures.length),
    signatures,
    uint32Le(identity.publicKeyDer.length),
    identity.publicKeyDer
  ]);
  const signers = encodeSequenceOfLengthPrefixedElements([signerBlock]);
  return encodeSequenceOfLengthPrefixedElements([signers]);
}

function buildApkSigningBlock(pairs: Array<[number, Uint8Array]>): Uint8Array {
  const encodedPairs = pairs.map(([id, value]) => concat([uint64Le(4 + value.length), uint32Le(id), value]));
  const pairsBytes = concat(encodedPairs);
  const blockSizeWithoutFirstSize = pairsBytes.length + 8 + APK_SIG_BLOCK_MAGIC.length;
  return concat([
    uint64Le(blockSizeWithoutFirstSize),
    pairsBytes,
    uint64Le(blockSizeWithoutFirstSize),
    APK_SIG_BLOCK_MAGIC
  ]);
}

export function computeV2ChunkedSha256Digest(contents: Uint8Array[]): Uint8Array {
  const chunkCount = contents.reduce((sum, bytes) => sum + Math.ceil(bytes.length / CHUNK_SIZE), 0);
  const concatOfDigests = new Uint8Array(5 + chunkCount * 32);
  concatOfDigests[0] = 0x5a;
  writeU32(concatOfDigests, 1, chunkCount);
  const chunkPrefix = new Uint8Array(5);
  chunkPrefix[0] = 0xa5;
  let chunkIndex = 0;

  for (const bytes of contents) {
    for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
      const chunk = bytes.slice(offset, Math.min(offset + CHUNK_SIZE, bytes.length));
      writeU32(chunkPrefix, 1, chunk.length);
      const md = forge.md.sha256.create();
      md.update(uint8ToBinary(chunkPrefix), "raw");
      md.update(uint8ToBinary(chunk), "raw");
      concatOfDigests.set(binaryToUint8(md.digest().getBytes()), 5 + chunkIndex * 32);
      chunkIndex++;
    }
  }

  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(concatOfDigests), "raw");
  return binaryToUint8(md.digest().getBytes());
}

function encodeSequenceOfLengthPrefixedElements(elements: Uint8Array[]): Uint8Array {
  return concat(elements.map((element) => concat([uint32Le(element.length), element])));
}

function encodeLengthPrefixedPairsOfIntAndLengthPrefixedBytes(pairs: Array<[number, Uint8Array]>): Uint8Array {
  return encodeSequenceOfLengthPrefixedElements(
    pairs.map(([id, value]) => concat([uint32Le(id), uint32Le(value.length), value]))
  );
}

function findZipSections(bytes: Uint8Array): ZipSections {
  const eocdOffset = findEocd(bytes);
  if (eocdOffset === -1) {
    throw new Error("Could not find ZIP end-of-central-directory record.");
  }
  return {
    eocdOffset,
    centralDirectoryOffset: readU32(bytes, eocdOffset + 16)
  };
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

function uint32Le(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  writeU32(bytes, 0, value);
  return bytes;
}

function uint64Le(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  writeU32(bytes, 0, value >>> 0);
  writeU32(bytes, 4, Math.floor(value / 0x100000000));
  return bytes;
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

function uint8ToBinary(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

function binaryToUint8(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

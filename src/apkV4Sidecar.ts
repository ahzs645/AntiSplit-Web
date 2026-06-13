import forge from "node-forge";
import { computeV2ChunkedSha256Digest } from "./apkV2Signer";
import { getDebugSigningIdentity } from "./apkV1Signer";

type V4SidecarResult = {
  idsigBytes: Uint8Array;
  treeBytes: Uint8Array;
  rootHash: Uint8Array;
  apkDigest: Uint8Array;
};

type V4VerificationResult = {
  verified: boolean;
  warnings: string[];
};

const EOCD_SIGNATURE = 0x06054b50;
const APK_SIG_BLOCK_MAGIC = new Uint8Array([
  0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
  0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
]);
const V4_VERSION = 2;
const HASHING_ALGORITHM_SHA256 = 1;
const LOG2_BLOCK_SIZE_4096 = 12;
const RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103;
const VERITY_BLOCK_SIZE = 4096;
const DIGEST_SIZE = 32;

export function generateV4Sidecar(apkBytes: Uint8Array): V4SidecarResult {
  const identity = getDebugSigningIdentity();
  const apkDigest = computeApkSigningContentDigest(apkBytes);
  const { treeBytes, rootHash } = computeVerityTreeAndRoot(apkBytes);
  const hashingInfo = encodeHashingInfo(rootHash);
  const signingInfoWithoutSignature = encodeSigningInfo(apkDigest, identity.certificateDer, new Uint8Array(0), identity.publicKeyDer, -1, new Uint8Array(0));
  const signedData = encodeV4SignedData(apkBytes.byteLength, hashingInfo, signingInfoWithoutSignature);
  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(signedData), "raw");
  const signature = binaryToUint8(identity.privateKey.sign(md));
  const signingInfo = encodeSigningInfo(apkDigest, identity.certificateDer, new Uint8Array(0), identity.publicKeyDer, RSA_PKCS1_V1_5_WITH_SHA256, signature);
  const idsigBytes = concat([
    uint32Le(V4_VERSION),
    bytesField(hashingInfo),
    bytesField(signingInfo),
    bytesField(treeBytes)
  ]);
  return {
    idsigBytes,
    treeBytes,
    rootHash,
    apkDigest
  };
}

export function verifyV4Sidecar(apkBytes: Uint8Array, idsigBytes: Uint8Array): V4VerificationResult {
  const warnings: string[] = [];
  let cursor = 0;
  if (idsigBytes.length < 4) {
    return { verified: false, warnings: ["v4 sidecar is too short."] };
  }
  const version = readU32(idsigBytes, cursor);
  cursor += 4;
  if (version !== V4_VERSION) {
    warnings.push(`Unexpected v4 sidecar version ${version}.`);
    return { verified: false, warnings };
  }
  const hashingInfoField = readBytesField(idsigBytes, cursor);
  if (!hashingInfoField) {
    return { verified: false, warnings: ["Malformed v4 hashingInfo field."] };
  }
  cursor = hashingInfoField.next;
  const signingInfoField = readBytesField(idsigBytes, cursor);
  if (!signingInfoField) {
    return { verified: false, warnings: ["Malformed v4 signingInfo field."] };
  }
  cursor = signingInfoField.next;
  const treeField = readBytesField(idsigBytes, cursor);
  if (!treeField || treeField.next !== idsigBytes.length) {
    return { verified: false, warnings: ["Malformed v4 verity tree field."] };
  }

  const hashingInfo = parseHashingInfo(hashingInfoField.value);
  const signingInfo = parseSigningInfo(signingInfoField.value);
  if (!hashingInfo || !signingInfo) {
    return { verified: false, warnings: ["Malformed v4 hashingInfo or signingInfo payload."] };
  }
  if (hashingInfo.hashAlgorithm !== HASHING_ALGORITHM_SHA256 || hashingInfo.log2BlockSize !== LOG2_BLOCK_SIZE_4096) {
    warnings.push("Unsupported v4 hashing parameters.");
    return { verified: false, warnings };
  }
  if (!bytesEqual(signingInfo.apkDigest, computeApkSigningContentDigest(apkBytes))) {
    warnings.push("v4 APK digest does not match the APK Signing Block content digest.");
    return { verified: false, warnings };
  }
  const { treeBytes, rootHash } = computeVerityTreeAndRoot(apkBytes);
  if (!bytesEqual(hashingInfo.rootHash, rootHash)) {
    warnings.push("v4 verity root hash does not match recomputed APK root hash.");
    return { verified: false, warnings };
  }
  if (!bytesEqual(treeField.value, treeBytes)) {
    warnings.push("v4 verity tree does not match recomputed APK tree.");
    return { verified: false, warnings };
  }
  if (signingInfo.signatureAlgorithmId !== RSA_PKCS1_V1_5_WITH_SHA256) {
    warnings.push("Unsupported v4 signature algorithm.");
    return { verified: false, warnings };
  }
  const signingInfoWithoutSignature = encodeSigningInfo(signingInfo.apkDigest, signingInfo.certificate, signingInfo.additionalData, signingInfo.publicKey, -1, new Uint8Array(0));
  const signedData = encodeV4SignedData(apkBytes.byteLength, hashingInfoField.value, signingInfoWithoutSignature);
  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(signedData), "raw");
  const forgePublicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(uint8ToBinary(signingInfo.publicKey))) as forge.pki.rsa.PublicKey;
  if (!forgePublicKey.verify(md.digest().getBytes(), uint8ToBinary(signingInfo.signature))) {
    warnings.push("RSA/SHA-256 signature over v4 signed-data did not verify.");
    return { verified: false, warnings };
  }
  return { verified: true, warnings };
}

function computeApkSigningContentDigest(apkBytes: Uint8Array): Uint8Array {
  const eocdOffset = findEocd(apkBytes);
  if (eocdOffset === -1) {
    throw new Error("Could not find ZIP end-of-central-directory record.");
  }
  const centralDirectoryOffset = readU32(apkBytes, eocdOffset + 16);
  const signingBlock = getSigningBlock(apkBytes, centralDirectoryOffset);
  if (!signingBlock) {
    throw new Error("APK Signing Block not found.");
  }
  const eocdForDigest = new Uint8Array(apkBytes.slice(eocdOffset));
  writeU32(eocdForDigest, 16, signingBlock.offset);
  return computeV2ChunkedSha256Digest([
    apkBytes.slice(0, signingBlock.offset),
    apkBytes.slice(centralDirectoryOffset, eocdOffset),
    eocdForDigest
  ]);
}

function computeVerityTreeAndRoot(data: Uint8Array): { treeBytes: Uint8Array; rootHash: Uint8Array } {
  const levels: Uint8Array[] = [];
  let levelSource = data;
  while (true) {
    const chunkCount = Math.ceil(levelSource.length / VERITY_BLOCK_SIZE);
    const unpaddedLength = chunkCount * DIGEST_SIZE;
    const levelLength = roundUp(unpaddedLength, VERITY_BLOCK_SIZE);
    const level = new Uint8Array(levelLength);
    for (let chunk = 0; chunk < chunkCount; chunk++) {
      const page = new Uint8Array(VERITY_BLOCK_SIZE);
      page.set(levelSource.slice(chunk * VERITY_BLOCK_SIZE, Math.min((chunk + 1) * VERITY_BLOCK_SIZE, levelSource.length)));
      level.set(sha256(page), chunk * DIGEST_SIZE);
    }
    levels.unshift(level);
    if (unpaddedLength <= VERITY_BLOCK_SIZE) {
      break;
    }
    levelSource = level;
  }
  const treeBytes = concat(levels);
  const firstPage = treeBytes.slice(0, VERITY_BLOCK_SIZE);
  return {
    treeBytes,
    rootHash: sha256(firstPage)
  };
}

function encodeHashingInfo(rootHash: Uint8Array): Uint8Array {
  return concat([
    uint32Le(HASHING_ALGORITHM_SHA256),
    new Uint8Array([LOG2_BLOCK_SIZE_4096]),
    bytesField(new Uint8Array(0)),
    bytesField(rootHash)
  ]);
}

function encodeSigningInfo(apkDigest: Uint8Array, certificate: Uint8Array, additionalData: Uint8Array, publicKey: Uint8Array, signatureAlgorithmId: number, signature: Uint8Array): Uint8Array {
  return concat([
    bytesField(apkDigest),
    bytesField(certificate),
    bytesField(additionalData),
    bytesField(publicKey),
    uint32Le(signatureAlgorithmId),
    bytesField(signature)
  ]);
}

function encodeV4SignedData(fileSize: number, hashingInfo: Uint8Array, signingInfo: Uint8Array): Uint8Array {
  const parsedHashing = parseHashingInfo(hashingInfo);
  const parsedSigning = parseSigningInfo(signingInfo);
  if (!parsedHashing || !parsedSigning) {
    throw new Error("Cannot encode v4 signed-data from malformed hashing/signing info.");
  }
  const size = 4 + 8 + 4 + 1 + fieldSize(parsedHashing.salt) + fieldSize(parsedHashing.rootHash) + fieldSize(parsedSigning.apkDigest) + fieldSize(parsedSigning.certificate) + fieldSize(parsedSigning.additionalData);
  return concat([
    uint32Le(size),
    uint64Le(fileSize),
    uint32Le(parsedHashing.hashAlgorithm),
    new Uint8Array([parsedHashing.log2BlockSize]),
    bytesField(parsedHashing.salt),
    bytesField(parsedHashing.rootHash),
    bytesField(parsedSigning.apkDigest),
    bytesField(parsedSigning.certificate),
    bytesField(parsedSigning.additionalData)
  ]);
}

function parseHashingInfo(bytes: Uint8Array): { hashAlgorithm: number; log2BlockSize: number; salt: Uint8Array; rootHash: Uint8Array } | null {
  if (bytes.length < 5) return null;
  let cursor = 0;
  const hashAlgorithm = readU32(bytes, cursor);
  cursor += 4;
  const log2BlockSize = bytes[cursor++];
  const salt = readBytesField(bytes, cursor);
  if (!salt) return null;
  cursor = salt.next;
  const rootHash = readBytesField(bytes, cursor);
  if (!rootHash || rootHash.next !== bytes.length) return null;
  return { hashAlgorithm, log2BlockSize, salt: salt.value, rootHash: rootHash.value };
}

function parseSigningInfo(bytes: Uint8Array): { apkDigest: Uint8Array; certificate: Uint8Array; additionalData: Uint8Array; publicKey: Uint8Array; signatureAlgorithmId: number; signature: Uint8Array } | null {
  let cursor = 0;
  const apkDigest = readBytesField(bytes, cursor);
  if (!apkDigest) return null;
  cursor = apkDigest.next;
  const certificate = readBytesField(bytes, cursor);
  if (!certificate) return null;
  cursor = certificate.next;
  const additionalData = readBytesField(bytes, cursor);
  if (!additionalData) return null;
  cursor = additionalData.next;
  const publicKey = readBytesField(bytes, cursor);
  if (!publicKey || publicKey.next + 4 > bytes.length) return null;
  cursor = publicKey.next;
  const signatureAlgorithmId = readU32(bytes, cursor);
  cursor += 4;
  const signature = readBytesField(bytes, cursor);
  if (!signature || signature.next !== bytes.length) return null;
  return { apkDigest: apkDigest.value, certificate: certificate.value, additionalData: additionalData.value, publicKey: publicKey.value, signatureAlgorithmId, signature: signature.value };
}

function getSigningBlock(bytes: Uint8Array, centralDirectoryOffset: number): { offset: number } | null {
  const footerOffset = centralDirectoryOffset - 24;
  if (footerOffset < 0 || !bytesEqual(bytes.slice(footerOffset + 8, footerOffset + 24), APK_SIG_BLOCK_MAGIC)) {
    return null;
  }
  const size = readU64Safe(bytes, footerOffset);
  const offset = centralDirectoryOffset - size - 8;
  if (offset < 0 || offset + 8 > bytes.length) {
    return null;
  }
  return { offset };
}

function bytesField(bytes: Uint8Array): Uint8Array {
  return concat([uint32Le(bytes.length), bytes]);
}

function readBytesField(bytes: Uint8Array, offset: number): { value: Uint8Array; next: number } | null {
  if (offset + 4 > bytes.length) return null;
  const length = readU32(bytes, offset);
  const start = offset + 4;
  const end = start + length;
  if (end > bytes.length) return null;
  return { value: bytes.slice(start, end), next: end };
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

function sha256(bytes: Uint8Array): Uint8Array {
  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(bytes), "raw");
  return binaryToUint8(md.digest().getBytes());
}

function fieldSize(bytes: Uint8Array): number {
  return 4 + bytes.length;
}

function roundUp(value: number, multiple: number): number {
  return Math.ceil(value / multiple) * multiple;
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

function readU64Safe(bytes: Uint8Array, offset: number): number {
  const low = readU32(bytes, offset);
  const high = readU32(bytes, offset + 4);
  return high * 0x100000000 + low;
}

function writeU32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
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

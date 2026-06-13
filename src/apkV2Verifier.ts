import forge from "node-forge";
import { computeV2ChunkedSha256Digest } from "./apkV2Signer";

type V2VerificationResult = {
  verified: boolean;
  signers: number;
  warnings: string[];
};

const EOCD_SIGNATURE = 0x06054b50;
const APK_V2_BLOCK_ID = 0x7109871a;
const RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103;
const APK_SIG_BLOCK_MAGIC = new Uint8Array([
  0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
  0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
]);

export function verifyV2Signature(apkBytes: Uint8Array): V2VerificationResult {
  const warnings: string[] = [];
  const eocdOffset = findEocd(apkBytes);
  if (eocdOffset === -1) {
    return { verified: false, signers: 0, warnings: ["Could not find ZIP end-of-central-directory record."] };
  }
  const centralDirectoryOffset = readU32(apkBytes, eocdOffset + 16);
  const block = getSigningBlock(apkBytes, centralDirectoryOffset);
  if (!block) {
    return { verified: false, signers: 0, warnings: ["APK Signing Block not found."] };
  }
  const v2Block = findSigningBlockPair(block.block, APK_V2_BLOCK_ID);
  if (!v2Block) {
    return { verified: false, signers: 0, warnings: ["APK Signature Scheme v2 pair not found."] };
  }

  const eocdForDigest = new Uint8Array(apkBytes.slice(eocdOffset));
  writeU32(eocdForDigest, 16, block.offset);
  const expectedDigest = computeV2ChunkedSha256Digest([
    apkBytes.slice(0, block.offset),
    apkBytes.slice(centralDirectoryOffset, eocdOffset),
    eocdForDigest
  ]);

  const signerSequence = readLengthPrefixedElement(v2Block, 0);
  if (!signerSequence || signerSequence.next !== v2Block.length) {
    return { verified: false, signers: 0, warnings: ["Malformed v2 signer sequence."] };
  }

  let cursor = 0;
  let signers = 0;
  while (cursor < signerSequence.value.length) {
    const signer = readLengthPrefixedElement(signerSequence.value, cursor);
    if (!signer) {
      warnings.push(`Malformed v2 signer at offset ${cursor}.`);
      break;
    }
    signers++;
    if (!verifySigner(signer.value, expectedDigest, warnings)) {
      return { verified: false, signers, warnings };
    }
    cursor = signer.next;
  }

  return {
    verified: signers > 0 && warnings.length === 0,
    signers,
    warnings
  };
}

function verifySigner(signer: Uint8Array, expectedDigest: Uint8Array, warnings: string[]): boolean {
  const signedData = readLengthPrefixedElement(signer, 0);
  if (!signedData) {
    warnings.push("Malformed v2 signer signed-data.");
    return false;
  }
  const signatures = readLengthPrefixedElement(signer, signedData.next);
  if (!signatures) {
    warnings.push("Malformed v2 signer signatures.");
    return false;
  }
  const publicKey = readLengthPrefixedElement(signer, signatures.next);
  if (!publicKey || publicKey.next !== signer.length) {
    warnings.push("Malformed v2 signer public key.");
    return false;
  }

  const digestOk = verifySignedDataDigest(signedData.value, expectedDigest, warnings);
  const signature = findIntLengthPrefixedBytes(signatures.value, RSA_PKCS1_V1_5_WITH_SHA256);
  if (!signature) {
    warnings.push("RSA/SHA-256 v2 signature record not found.");
    return false;
  }

  const md = forge.md.sha256.create();
  md.update(uint8ToBinary(signedData.value), "raw");
  const forgePublicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(uint8ToBinary(publicKey.value))) as forge.pki.rsa.PublicKey;
  const signatureOk = forgePublicKey.verify(md.digest().getBytes(), uint8ToBinary(signature));
  if (!signatureOk) {
    warnings.push("RSA/SHA-256 signature over v2 signed-data did not verify.");
  }
  return digestOk && signatureOk;
}

function verifySignedDataDigest(signedData: Uint8Array, expectedDigest: Uint8Array, warnings: string[]): boolean {
  const digests = readLengthPrefixedElement(signedData, 0);
  if (!digests) {
    warnings.push("Malformed v2 signed-data digests.");
    return false;
  }
  const actualDigest = findIntLengthPrefixedBytes(digests.value, RSA_PKCS1_V1_5_WITH_SHA256);
  if (!actualDigest) {
    warnings.push("RSA/SHA-256 digest record not found.");
    return false;
  }
  if (!bytesEqual(actualDigest, expectedDigest)) {
    warnings.push("v2 content digest did not match recomputed APK digest.");
    return false;
  }
  return true;
}

function getSigningBlock(bytes: Uint8Array, centralDirectoryOffset: number): { offset: number; block: Uint8Array } | null {
  const footerOffset = centralDirectoryOffset - 24;
  if (footerOffset < 0 || !bytesEqual(bytes.slice(footerOffset + 8, footerOffset + 24), APK_SIG_BLOCK_MAGIC)) {
    return null;
  }
  const size = readU64Safe(bytes, footerOffset);
  const offset = centralDirectoryOffset - size - 8;
  if (offset < 0 || offset + 8 > bytes.length) {
    return null;
  }
  return {
    offset,
    block: bytes.slice(offset, centralDirectoryOffset)
  };
}

function findSigningBlockPair(block: Uint8Array, id: number): Uint8Array | null {
  let cursor = 8;
  const pairsEnd = block.length - 24;
  while (cursor + 12 <= pairsEnd) {
    const size = readU64Safe(block, cursor);
    if (size < 4 || cursor + 8 + size > pairsEnd) {
      return null;
    }
    const pairId = readU32(block, cursor + 8);
    if (pairId === id) {
      return block.slice(cursor + 12, cursor + 8 + size);
    }
    cursor += 8 + size;
  }
  return null;
}

function findIntLengthPrefixedBytes(sequence: Uint8Array, id: number): Uint8Array | null {
  let cursor = 0;
  while (cursor < sequence.length) {
    const item = readLengthPrefixedElement(sequence, cursor);
    if (!item || item.value.length < 8) {
      return null;
    }
    if (readU32(item.value, 0) === id) {
      const bytesLength = readU32(item.value, 4);
      if (8 + bytesLength > item.value.length) {
        return null;
      }
      return item.value.slice(8, 8 + bytesLength);
    }
    cursor = item.next;
  }
  return null;
}

function readLengthPrefixedElement(bytes: Uint8Array, offset: number): { value: Uint8Array; next: number } | null {
  if (offset + 4 > bytes.length) {
    return null;
  }
  const length = readU32(bytes, offset);
  const start = offset + 4;
  const end = start + length;
  if (end > bytes.length) {
    return null;
  }
  return {
    value: bytes.slice(start, end),
    next: end
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

function uint8ToBinary(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

import forge from "node-forge";
import { DEBUG_PRIVATE_KEY_PEM } from "./debugSigningKey";

type SignatureFiles = {
  manifest: Uint8Array;
  signatureFile: Uint8Array;
  signatureBlock: Uint8Array;
  certificateDer: Uint8Array;
};

export type V1DigestAlgorithm = "sha1" | "sha256";

type V1SignatureOptions = {
  digestAlgorithm?: V1DigestAlgorithm;
  onDigestProgress?: (progress: V1DigestProgress) => void;
};

export type V1DigestProgress = {
  currentEntry: string;
  processedBytes: number;
  totalBytes: number;
  processedEntries: number;
  totalEntries: number;
};

export type SigningIdentity = {
  privateKey: forge.pki.rsa.PrivateKey;
  certificate: forge.pki.Certificate;
  certificateDer: Uint8Array;
  publicKeyDer: Uint8Array;
};

const encoder = new TextEncoder();
const SIGNATURE_ENTRY_RE = /^META-INF\/(?:[^/]+\.(?:RSA|DSA|EC|SF)|MANIFEST\.MF)$/i;
let cachedIdentity: {
  privateKey: forge.pki.rsa.PrivateKey;
  certificate: forge.pki.Certificate;
} | null = null;

export function createV1SignatureFiles(entries: Record<string, Uint8Array>, options: V1SignatureOptions = {}): SignatureFiles {
  const digestAlgorithm = options.digestAlgorithm ?? "sha256";
  const digestField = digestAlgorithm === "sha1" ? "SHA1-Digest" : "SHA-256-Digest";
  const manifestDigestField = digestAlgorithm === "sha1" ? "SHA1-Digest-Manifest" : "SHA-256-Digest-Manifest";
  const signableEntries = Object.entries(entries)
    .filter(([name]) => !SIGNATURE_ENTRY_RE.test(name) && !name.endsWith("/"))
    .sort(([a], [b]) => a.localeCompare(b));
  const totalBytes = signableEntries.reduce((sum, [, bytes]) => sum + bytes.byteLength, 0);
  let processedBytes = 0;
  let processedEntries = 0;

  const manifestSections: Array<{ name: string; text: string }> = [];
  const manifestMain = "Manifest-Version: 1.0\r\nCreated-By: AntiSplit Web\r\n\r\n";

  for (const [name, bytes] of signableEntries) {
    manifestSections.push({
      name,
      text: wrapManifestSection(
        `Name: ${name}\r\n${digestField}: ${digestBase64(bytes, digestAlgorithm, (chunkBytes) => {
          processedBytes += chunkBytes;
          options.onDigestProgress?.({
            currentEntry: name,
            processedBytes,
            totalBytes,
            processedEntries,
            totalEntries: signableEntries.length
          });
        })}\r\n\r\n`
      )
    });
    processedEntries++;
    options.onDigestProgress?.({
      currentEntry: name,
      processedBytes,
      totalBytes,
      processedEntries,
      totalEntries: signableEntries.length
    });
  }

  const manifestText = manifestMain + manifestSections.map((section) => section.text).join("");
  const manifest = encoder.encode(manifestText);
  const signatureSections = manifestSections
    .map(({ name, text }) => {
      const nameLine = wrapManifestLine(`Name: ${name}`);
      return `${nameLine}\r\n${digestField}: ${digestBase64(encoder.encode(text), digestAlgorithm)}\r\n\r\n`;
    })
    .join("");

  const signatureFileText = wrapManifestSection(
    `Signature-Version: 1.0\r\nCreated-By: AntiSplit Web\r\n${manifestDigestField}: ${digestBase64(manifest, digestAlgorithm)}\r\n\r\n`
  ) + signatureSections;
  const signatureFile = encoder.encode(signatureFileText);
  const { privateKey, certificate } = getSigningIdentity();

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(uint8ToBinary(signatureFile));
  p7.addCertificate(certificate);
  const signer: {
    key: forge.pki.rsa.PrivateKey;
    certificate: forge.pki.Certificate;
    digestAlgorithm: string;
    authenticatedAttributes?: Array<{ type: string; value?: string }>;
  } = {
    key: privateKey,
    certificate,
    digestAlgorithm: digestAlgorithm === "sha1" ? forge.pki.oids.sha1 : forge.pki.oids.sha256
  };
  if (digestAlgorithm !== "sha1") {
    signer.authenticatedAttributes = [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data
      },
      {
        type: forge.pki.oids.messageDigest
      }
    ];
  }
  p7.addSigner(signer);
  p7.sign({ detached: true });

  const signatureBlock = binaryToUint8(forge.asn1.toDer(p7.toAsn1()).getBytes());
  const certificateDer = binaryToUint8(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes());

  return {
    manifest,
    signatureFile,
    signatureBlock,
    certificateDer
  };
}

export function getDebugSigningIdentity(): SigningIdentity {
  const { privateKey, certificate } = getSigningIdentity();
  return {
    privateKey,
    certificate,
    certificateDer: binaryToUint8(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes()),
    publicKeyDer: binaryToUint8(forge.asn1.toDer(forge.pki.publicKeyToAsn1(certificate.publicKey)).getBytes())
  };
}

function getSigningIdentity() {
  if (cachedIdentity) {
    return cachedIdentity;
  }

  const privateKey = forge.pki.privateKeyFromPem(DEBUG_PRIVATE_KEY_PEM) as forge.pki.rsa.PrivateKey;
  const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = "4153574542000001";
  cert.validity.notBefore = new Date("2024-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2124-01-01T00:00:00Z");
  const attrs = [
    { name: "commonName", value: "AntiSplit Web Debug" },
    { name: "organizationName", value: "AntiSplit Web" },
    { shortName: "C", value: "US" }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true }
  ]);
  cert.sign(privateKey, forge.md.sha256.create());

  cachedIdentity = {
    privateKey,
    certificate: cert
  };
  return cachedIdentity;
}

function digestBase64(
  bytes: Uint8Array,
  digestAlgorithm: V1DigestAlgorithm,
  onChunk?: (processedBytes: number) => void
): string {
  const md = digestAlgorithm === "sha1" ? forge.md.sha1.create() : forge.md.sha256.create();
  const chunkSize = 1024 * 1024;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.byteLength));
    md.update(uint8ToBinary(chunk), "raw");
    onChunk?.(chunk.byteLength);
  }
  return forge.util.encode64(md.digest().getBytes());
}

function wrapManifestSection(section: string): string {
  return section
    .split("\r\n")
    .map((line) => wrapManifestLine(line))
    .join("\r\n");
}

function wrapManifestLine(line: string): string {
  const bytes = encoder.encode(line);
  if (bytes.length <= 70) {
    return line;
  }

  let remaining = line;
  const lines: string[] = [];
  let first = true;
  while (encoder.encode(remaining).length > (first ? 70 : 69)) {
    const limit = first ? 70 : 69;
    let cut = Math.min(remaining.length, limit);
    while (encoder.encode(remaining.slice(0, cut)).length > limit) {
      cut--;
    }
    lines.push(`${first ? "" : " "}${remaining.slice(0, cut)}`);
    remaining = remaining.slice(cut);
    first = false;
  }
  lines.push(`${first ? "" : " "}${remaining}`);
  return lines.join("\r\n");
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

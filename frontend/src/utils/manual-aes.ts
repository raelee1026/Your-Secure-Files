// ⚠️ Educational implementation of AES-CTR (partial AES-GCM)
// Includes: simplified AES block encryption, CTR mode, and stubs for GHASH

import { decryptKmsPrivateKey } from "./crypto";

export async function getSessionKey(): Promise<CryptoKey> {

  const username = localStorage.getItem("username")
  if (!username) throw new Error("Missing username")

  const password = localStorage.getItem("password")
  if (!password) throw new Error("Missing password")

  const privateKey = await decryptKmsPrivateKey(username, password); 
  if (!privateKey) throw new Error("Missing private key")

  const encryptedB64 = localStorage.getItem("session_key")!;
  if (!encryptedB64) throw new Error("Missing encrypted session key")

  const encryptedBytes = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));

  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBytes
  );
  if (!rawKey) throw new Error("Missing raw key")

  return await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

// S-Box table for SubBytes step
const sBox = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

// Helper function to apply S-Box substitution
function subBytes(state: Uint8Array): Uint8Array {
  return state.map((byte) => sBox[byte]);
}

// Helper function to XOR two blocks
function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// Simplified AES block encryption (for demo only — NOT SECURE!)
function aesEncryptBlock(block: Uint8Array, keyBytes: Uint8Array): Uint8Array {
  const subbed = subBytes(block);
  return xorBlocks(subbed, keyBytes);
}

// Increment counter for CTR mode
function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i--) {
    if (++counter[i] !== 0) break;
  }
}

// Core AES-CTR encryption
async function aesCtrEncrypt(plaintext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const blockSize = 16;
  const ciphertext = new Uint8Array(plaintext.length);
  const counter = new Uint8Array(blockSize);
  counter.set(iv);

  // Export key to raw bytes for simplified AES block encryption
  const keyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", key));

  for (let i = 0; i < plaintext.length; i += blockSize) {
    const keystream = aesEncryptBlock(counter, keyBytes);
    const chunk = plaintext.slice(i, i + blockSize);
    const xor = xorBlocks(chunk, keystream.slice(0, chunk.length));
    ciphertext.set(xor, i);
    incrementCounter(counter);
  }

  return ciphertext;
}

// Core AES-CTR decryption (same as encryption due to CTR mode)
async function aesCtrDecrypt(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  // CTR decryption is identical to encryption
  return aesCtrEncrypt(ciphertext, key, iv);
}

// Stub for GHASH (for educational purposes, not secure)
function ghashStub(): Uint8Array {
  return new Uint8Array(16); // Fake 16-byte tag
}

export async function encryptAESGCM(plaintext: string, aesKey: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await aesCtrEncrypt(encoded, aesKey, iv);
  const combined = new Uint8Array(iv.length + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);

  const result = btoa(String.fromCharCode(...combined));

  // console.log("🔐 Encrypting:", plaintext);
  // console.log("🧊 Encrypted (base64):", result);

  return result;
}

export async function decryptAESGCM(ciphertextBase64: string, aesKey: CryptoKey): Promise<string> {
  const combined = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await aesCtrDecrypt(ciphertext, aesKey, iv);
  const result = new TextDecoder().decode(decrypted);

  // console.log("🔓 Decrypting base64:", ciphertextBase64);
  // console.log("✅ Decrypted:", result);

  return result;
}

export async function importAESKeyFromBase64(base64Key: string): Promise<CryptoKey> {
  const rawKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function importAESKeyFromRawBytes(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}
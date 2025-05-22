// ⚠️ Educational implementation of AES-CTR with simplified AES-GCM features
// Includes: custom key expansion, 15 AES rounds, and manual key handling
import { decryptKmsPrivateKey } from "./crypto";

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

/**
 * Applies S-Box substitution to the input state.
 * @param state 16-byte block to transform
 * @returns Transformed block
 * @throws Error if block size is invalid
 */
function subBytes(state: Uint8Array): Uint8Array {
  if (state.length !== 16) throw new Error("Invalid block size for SubBytes");
  return state.map((byte) => sBox[byte]);
}

/**
 * Performs ShiftRows transformation on the state.
 * @param state 16-byte block to transform
 * @returns Transformed block
 * @throws Error if block size is invalid
 */
function shiftRows(state: Uint8Array): Uint8Array {
  if (state.length !== 16) throw new Error("Invalid block size for ShiftRows");
  const result = new Uint8Array(16);
  result[0] = state[0]; result[4] = state[4]; result[8] = state[8]; result[12] = state[12];
  result[1] = state[5]; result[5] = state[9]; result[9] = state[13]; result[13] = state[1];
  result[2] = state[10]; result[6] = state[14]; result[10] = state[2]; result[14] = state[6];
  result[3] = state[15]; result[7] = state[3]; result[11] = state[7]; result[15] = state[11];
  return result;
}

/**
 * Simplified MixColumns transformation (educational use).
 * @param state 16-byte block to transform
 * @returns Transformed block
 * @throws Error if block size is invalid
 */
function mixColumns(state: Uint8Array): Uint8Array {
  if (state.length !== 16) throw new Error("Invalid block size for MixColumns");
  const result = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = state[i], a1 = state[i + 1], a2 = state[i + 2], a3 = state[i + 3];
    result[i] = a0 ^ a1;
    result[i + 1] = a1 ^ a2;
    result[i + 2] = a2 ^ a3;
    result[i + 3] = a3 ^ a0;
  }
  return result;
}

/**
 * XORs two blocks of equal length.
 * @param a First block
 * @param b Second block
 * @returns XOR result
 * @throws Error if block sizes differ
 */
function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error("Mismatched block sizes for XOR");
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Simplified key expansion for educational AES (generates 15 round keys).
 * @param keyBytes 16-byte key
 * @returns Array of 15 round keys (16 bytes each)
 * @throws Error if key size is invalid
 */
function expandKey(keyBytes: Uint8Array): Uint8Array[] {

    console.log("start expandKey", keyBytes);
  if (keyBytes.length !== 16) throw new Error("Invalid key size for expansion");
  const roundKeys = [new Uint8Array(keyBytes)];
  for (let i = 1; i < 15; i++) {
    const prevKey = roundKeys[i - 1];
    const newKey = new Uint8Array(16);
    const rotated = new Uint8Array([prevKey[13], prevKey[14], prevKey[15], prevKey[12]]);
    console.log("rotated", rotated);
    const subbed = subBytes(rotated);
    newKey.set(xorBlocks(subbed, prevKey.slice(0, 4)), 0);
    for (let j = 4; j < 16; j++) {
      newKey[j] = prevKey[j] ^ newKey[j - 4];
    }
    roundKeys.push(newKey);
  }
  console.log("end expandKey", roundKeys);
  return roundKeys;
}

/**
 * Simplified AES block encryption with 15 rounds (educational, NOT SECURE).
 * @param block 16-byte block to encrypt
 * @param roundKeys Array of 15 round keys
 * @returns Encrypted block
 * @throws Error if block or key sizes are invalid
 */
function aesEncryptBlock(block: Uint8Array, roundKeys: Uint8Array[]): Uint8Array {
  if (block.length !== 16) throw new Error("Invalid block size for AES");
  if (roundKeys.length !== 15) throw new Error("Invalid round key count; expected 15");
  let state = new Uint8Array(block);
  for (let i = 0; i < roundKeys.length; i++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = i < roundKeys.length - 1 ? mixColumns(state) : state; // Skip MixColumns in last round
    state = xorBlocks(state, roundKeys[i]);
  }
  return state;
}

/**
 * Increments the counter for CTR mode.
 * @param counter 16-byte counter
 * @throws Error if counter size is invalid
 */
function incrementCounter(counter: Uint8Array): void {
  if (counter.length !== 16) throw new Error("Invalid counter size");
  for (let i = counter.length - 1; i >= 0; i--) {
    if (++counter[i] !== 0) break;
  }
}

/**
 * Simplified GHASH-like function (educational, NOT SECURE).
 * @param data Input data to hash
 * @param keyBytes 16-byte hash key
 * @returns 16-byte tag
 * @throws Error if key size is invalid
 */
function simplifiedGhash(data: Uint8Array, keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.length !== 16) throw new Error("Invalid GHASH key size");
  const tag = new Uint8Array(16);
  let temp = new Uint8Array(16);
  const roundKeys = expandKey(keyBytes);
  for (let i = 0; i < data.length; i += 16) {
    const block = data.slice(i, i + 16);
    temp = xorBlocks(temp, block.length === 16 ? block : new Uint8Array(16));
    temp = aesEncryptBlock(temp, roundKeys);
  }
  tag.set(temp);
  return tag;
}

/**
 * Core AES-CTR encryption.
 * @param plaintext Input data
 * @param roundKeys Array of 15 round keys
 * @param iv 12-byte initialization vector
 * @returns Encrypted data
 * @throws Error if IV or key sizes are invalid
 */
async function aesCtrEncrypt(plaintext: Uint8Array, roundKeys: Uint8Array[], iv: Uint8Array): Promise<Uint8Array> {
  if (iv.length !== 12) throw new Error("IV must be 12 bytes");
  if (roundKeys.length !== 15) throw new Error("Invalid round key count; expected 15");
  const blockSize = 16;
  const ciphertext = new Uint8Array(plaintext.length);
  const counter = new Uint8Array(blockSize);
  counter.set(iv);

  for (let i = 0; i < plaintext.length; i += blockSize) {
    const keystream = aesEncryptBlock(counter, roundKeys);
    const chunk = plaintext.slice(i, i + blockSize);
    const xor = xorBlocks(chunk, keystream.slice(0, chunk.length));
    ciphertext.set(xor, i);
    incrementCounter(counter);
  }

  return ciphertext;
}

/**
 * Core AES-CTR decryption (same as encryption due to CTR mode).
 * @param ciphertext Input data
 * @param roundKeys Array of 15 round keys
 * @param iv 12-byte initialization vector
 * @returns Decrypted data
 * @throws Error if IV or key sizes are invalid
 */
async function aesCtrDecrypt(ciphertext: Uint8Array, roundKeys: Uint8Array[], iv: Uint8Array): Promise<Uint8Array> {
  return aesCtrEncrypt(ciphertext, roundKeys, iv); // CTR mode is symmetric
}

/**
 * Retrieves the session key from localStorage, decrypting with RSA-OAEP.
 * @returns Array of 15 round keys (16 bytes each)
 * @throws Error if required data is missing
 */
export async function getSessionKey(): Promise<Uint8Array[]> {
  const username = localStorage.getItem("username");
  if (!username) throw new Error("Missing username in localStorage");

  const password = localStorage.getItem("password");
  if (!password) throw new Error("Missing password in localStorage");

  const privateKey = await decryptKmsPrivateKey(username, password);
  if (!privateKey) throw new Error("Failed to decrypt private key");

  const encryptedB64 = localStorage.getItem("session_key");
  if (!encryptedB64) throw new Error("Missing encrypted session key in localStorage");

  const encryptedBytes = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));

  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBytes
  );
  if (!rawKey) throw new Error("Failed to decrypt session key");

  const keyBytes = new Uint8Array(rawKey);
  if (keyBytes.length !== 16) throw new Error("Invalid session key length");

  const roundKeys = expandKey(keyBytes);
  // console.log("🔑 Retrieved session key with 15 round keys (educational use)");
  return roundKeys;
}

/**
 * Encrypts plaintext using AES-CTR with a simplified GHASH tag.
 * @param plaintext Text to encrypt
 * @param roundKeys Array of 15 round keys
 * @returns Base64-encoded IV + ciphertext + tag
 * @throws Error if inputs are invalid
 */
export async function encryptAESGCM(plaintext: string, roundKeys: Uint8Array[]): Promise<string> {
  if (!plaintext) throw new Error("Plaintext cannot be empty");
  if (roundKeys.length !== 15) throw new Error("Invalid round key count; expected 15");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await aesCtrEncrypt(encoded, roundKeys, iv);
  const keyBytes = roundKeys[0]; // Use first round key for GHASH
  const tag = simplifiedGhash(ciphertext, keyBytes);

  const combined = new Uint8Array(iv.length + ciphertext.length + tag.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);
  combined.set(tag, iv.length + ciphertext.length);

  const result = btoa(String.fromCharCode(...combined));

  // console.log("🔐 Encrypting:", plaintext);
  // console.log("🧊 Encrypted (base64):", result);
  return result;
}

/**
 * Decrypts base64-encoded ciphertext using AES-CTR and verifies GHASH tag.
 * @param ciphertextBase64 Base64-encoded IV + ciphertext + tag
 * @param roundKeys Array of 15 round keys
 * @returns Decrypted plaintext
 * @throws Error if inputs or tag verification fail
 */
export async function decryptAESGCM(ciphertextBase64: string, roundKeys: Uint8Array[]): Promise<string> {
  if (!ciphertextBase64) throw new Error("Ciphertext cannot be empty");
  if (roundKeys.length !== 15) throw new Error("Invalid round key count; expected 15");
  const combined = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
  if (combined.length < 28) throw new Error("Invalid ciphertext format (too short)");

  const iv = combined.slice(0, 12);
  const tag = combined.slice(combined.length - 16);
  const ciphertext = combined.slice(12, combined.length - 16);

  const keyBytes = roundKeys[0]; // Use first round key for GHASH
  const computedTag = simplifiedGhash(ciphertext, keyBytes);
  if (!tag.every((val, i) => val === computedTag[i])) {
    throw new Error("Authentication tag verification failed");
  }

  const decrypted = await aesCtrDecrypt(ciphertext, roundKeys, iv);
  const result = new TextDecoder().decode(decrypted);

  // console.log("🔓 Decrypting base64:", ciphertextBase64);
  // console.log("✅ Decrypted:", result);
  return result;
}

/**
 * Imports an AES key from a base64-encoded string.
 * @param base64Key Base64-encoded key
 * @returns Array of 15 round keys
 * @throws Error if key is invalid
 */
export async function importAESKeyFromBase64(base64Key: string): Promise<Uint8Array[]> {
  if (!base64Key) throw new Error("Base64 key cannot be empty");
  const rawKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  if (rawKey.length !== 16) throw new Error("Invalid key length");
  return expandKey(rawKey);
}

/**
 * Imports an AES key from raw bytes.
 * @param raw Raw key bytes
 * @returns Array of 15 round keys
 * @throws Error if key is invalid
 */
export async function importAESKeyFromRawBytes(raw: ArrayBuffer): Promise<Uint8Array[]> {
  if (raw.byteLength !== 16) throw new Error("Invalid key length");
  const keyBytes = new Uint8Array(raw);
  return expandKey(keyBytes);
}
// decrypt base64(nonce + ciphertext) with AES-GCM
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


export async function decryptAESGCM(ciphertextBase64: string, aesKey: CryptoKey): Promise<string> {
  const combined = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  const result = new TextDecoder().decode(decrypted);

  // ✅ Log
  console.log("🔓 Decrypting base64:", ciphertextBase64);
  console.log("✅ Decrypted:", result);

  return result;
}

export async function encryptAESGCM(plaintext: string, aesKey: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  const result = btoa(String.fromCharCode(...combined));

  // ✅ Log
  console.log("🔐 Encrypting:", plaintext);
  console.log("🧊 Encrypted (base64):", result);

  return result;
}
// import base64 string as AES CryptoKey

export async function importAESKeyFromBase64(base64Key: string): Promise<CryptoKey> {
  const rawKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
}
// --- AES-GCM encryption/decryption ---


export async function importAESKeyFromRawBytes(raw: ArrayBuffer): Promise<CryptoKey> {
  return await window.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}


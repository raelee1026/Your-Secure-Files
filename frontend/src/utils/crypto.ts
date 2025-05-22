import { importAESKeyFromRawBytes } from "./aes";
import { openDB } from 'idb';

export async function decryptKmsPrivateKey(
  username: string,
  password: string
): Promise<CryptoKey> {
  const db = await openDB("KeyStore", 1);
  const encryptedData = await db.get("keys", username);
  db.close();

  if (!encryptedData) throw new Error("Private key not found");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(encryptedData.salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(encryptedData.iv) },
    derivedKey,
    new Uint8Array(encryptedData.encrypted)
  );

  const jwkPrivateKey = JSON.parse(new TextDecoder().decode(decrypted));

  // 🔧 為了與 Web Crypto 相容，移除干擾欄位
  delete jwkPrivateKey.alg;
  delete jwkPrivateKey.key_ops;

  return await crypto.subtle.importKey(
    "jwk",
    jwkPrivateKey,
    { name: "RSA-OAEP", hash: "SHA-256" }, // ✅ 與後端完全一致
    true,
    ["decrypt"]
  );
}


// export async function decryptKmsPrivateKey(
//   username: string,
//   password: string
// ): Promise<CryptoKey> {
//   const db = await openDB("KeyStore", 1);
//   const encryptedData = await db.get("keys", username);
//   db.close();

//   if (!encryptedData) throw new Error("Private key not found");

//   const key = await window.crypto.subtle.importKey(
//     "raw",
//     new TextEncoder().encode(password),
//     { name: "PBKDF2" },
//     false,
//     ["deriveKey"]
//   );

//   const derivedKey = await window.crypto.subtle.deriveKey(
//     {
//       name: "PBKDF2",
//       salt: new Uint8Array(encryptedData.salt),
//       iterations: 100000,
//       hash: "SHA-256",
//     },
//     key,
//     { name: "AES-GCM", length: 256 },
//     false,
//     ["decrypt"]
//   );

//   const decrypted = await window.crypto.subtle.decrypt(
//     { name: "AES-GCM", iv: new Uint8Array(encryptedData.iv) },
//     derivedKey,
//     new Uint8Array(encryptedData.encrypted)
//   );

//   const jwkPrivateKey = JSON.parse(new TextDecoder().decode(decrypted));

//   if (!jwkPrivateKey.d || !jwkPrivateKey.n || !jwkPrivateKey.e) {
//     throw new Error("Invalid JWK: missing RSA private key fields (d, n, e)");
//   }

//   return window.crypto.subtle.importKey(
//     "jwk",
//     jwkPrivateKey,
//     { name: "RSA-OAEP", hash: "SHA-256" },
//     true,
//     ["decrypt"]
//   );
// }


export async function getDecryptedSessionKey(username: string, password: string): Promise<CryptoKey> {
  const encryptedKeyB64 = localStorage.getItem("session_key")
  if (!encryptedKeyB64) throw new Error("Missing encrypted session key")

  const privateKey = await decryptKmsPrivateKey(username, password)
  const rawKey = await decryptWithPrivateKey(privateKey, encryptedKeyB64)
  return await importAESKeyFromRawBytes(rawKey)
}

// 解密從後端拿到的 session_key_encrypted（Base64 編碼的 RSA 密文）
export async function decryptWithPrivateKey(
  privateKey: CryptoKey,
  encryptedBase64: string
): Promise<ArrayBuffer> {
  const ciphertext = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0))
  return await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP", // 或 RSASSA-PKCS1-v1_5，根據後端用哪個演算法
    },
    privateKey,
    ciphertext
  )
}

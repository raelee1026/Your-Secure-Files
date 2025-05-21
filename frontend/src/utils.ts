import type { ApiError } from "./client"
import useCustomToast from "./hooks/useCustomToast"
import { openDB } from 'idb';

export const emailPattern = {
  value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
  message: "Invalid email address",
}

export const namePattern = {
  value: /^[A-Za-z\s\u00C0-\u017F]{1,30}$/,
  message: "Invalid name",
}

export const passwordRules = (isRequired = true) => {
  const rules: any = {
    minLength: {
      value: 8,
      message: "Password must be at least 8 characters",
    },
  }

  if (isRequired) {
    rules.required = "Password is required"
  }

  return rules
}

export const confirmPasswordRules = (
  getValues: () => any,
  isRequired = true,
) => {
  const rules: any = {
    validate: (value: string) => {
      const password = getValues().password || getValues().new_password
      return value === password ? true : "The passwords do not match"
    },
  }

  if (isRequired) {
    rules.required = "Password confirmation is required"
  }

  return rules
}

export const handleError = (err: ApiError) => {
  const { showErrorToast } = useCustomToast()
  const errDetail = (err.body as any)?.detail
  let errorMessage = errDetail || "Something went wrong."
  if (Array.isArray(errDetail) && errDetail.length > 0) {
    errorMessage = errDetail[0].msg
  }
  showErrorToast(errorMessage)
}

// Use Web Crypto API to generate RSA key pair
export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"] 
  );
}

// 將 CryptoKey 公鑰匯出為 PEM 格式字串
export async function exportPublicKeyToPEM(publicKey: CryptoKey): Promise<string> {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
  const pem = [
    "-----BEGIN PUBLIC KEY-----",
    ...b64.match(/.{1,64}/g)!,
    "-----END PUBLIC KEY-----",
  ].join("\n");
  return pem;
}

async function encryptPrivateKey(privateKey: CryptoKey, password: string): Promise<{ iv: Uint8Array; salt: Uint8Array; encrypted: Uint8Array }> {
  //console.log("encryptPrivateKey ", password);
  try {
    // Generate a random salt for PBKDF2
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    // Generate a random IV for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Derive a key from the password using PBKDF2
    const key = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      key,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // Export the private key to JWK format
    const jwkPrivateKey = await window.crypto.subtle.exportKey("jwk", privateKey);
    const jwkString = JSON.stringify(jwkPrivateKey);
    const encodedData = new TextEncoder().encode(jwkString);

    // Encrypt the private key
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      derivedKey,
      encodedData
    );

    return {
      iv: new Uint8Array(iv),
      salt: new Uint8Array(salt),
      encrypted: new Uint8Array(encrypted),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    throw new Error(`Failed to encrypt private key: ${errorMessage}`);
  }
}
export async function savePrivateKey(privateKey: CryptoKey, username: string, password: string): Promise<void> {
  try {
    const encryptedData = await encryptPrivateKey(privateKey, password); // 會包含 iv + salt
    const db = await openDB("KeyStore", 1, {
      upgrade(db) {
        if (!db.objectStoreNames.contains("keys")) {
          db.createObjectStore("keys");
        }
      },
    });
    await db.put("keys", encryptedData, username);
    db.close();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    throw new Error(`Failed to save private key to IndexedDB: ${errorMessage}`);
  }
}

export async function decryptPrivateKey(username: string, password: string): Promise<CryptoKey> {
  //console.log("decryptPrivateKey ", username, password);
  const db = await openDB("KeyStore", 1);
  const encryptedData = await db.get("keys", username);
  db.close();

  if (!encryptedData) throw new Error("Private key not found");

  const key = await window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const derivedKey = await window.crypto.subtle.deriveKey(
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

  let decrypted;
  try {
    decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(encryptedData.iv) },
      derivedKey,
      new Uint8Array(encryptedData.encrypted)
    );
  } catch (e) {
    console.error("Decryption failed. Wrong password or corrupted data.");
    throw e;
  }

  const jwkPrivateKey = JSON.parse(new TextDecoder().decode(decrypted));
  //console.log("Decrypted JWK:", jwkPrivateKey);

  if (!jwkPrivateKey.d || !jwkPrivateKey.n || !jwkPrivateKey.e) {
    throw new Error("Invalid JWK: missing RSA private key fields (d, n, e)");
  }

  return window.crypto.subtle.importKey(
    "jwk",
    jwkPrivateKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["sign"]
  );
}
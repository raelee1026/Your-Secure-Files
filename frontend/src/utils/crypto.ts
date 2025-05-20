// generate RSA key pair
export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  return window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  )
}

// export public key as PEM format (for storage in localStorage)
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const spki = await window.crypto.subtle.exportKey("spki", key)
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)))
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`
}

// export private key as PEM format (for storage in localStorage)
export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", key)
  const b64 = window.btoa(String.fromCharCode(...new Uint8Array(pkcs8)))
  return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`
}

// load PEM format public key
export async function importPublicKey(pem: string): Promise<CryptoKey> {
  const b64 = pem.replace(/-----.*?-----/g, "").replace(/\s/g, "")
  const der = Uint8Array.from(window.atob(b64), c => c.charCodeAt(0))
  return window.crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"]
  )
}

// load PEM format private key
export async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const b64 = pem.replace(/-----.*?-----/g, "").replace(/\s/g, "")
  const der = Uint8Array.from(window.atob(b64), c => c.charCodeAt(0))
  return window.crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["sign"]
  )
}

// sign data with private key
export async function signWithPrivateKey(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    data
  )
}

// verify signature with public key
export async function verifyWithPublicKey(publicKey: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKey,
    signature,
    data
  )
}
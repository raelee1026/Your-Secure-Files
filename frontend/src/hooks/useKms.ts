import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

interface KeyRequestPayload {
  username: string;
  signature_b64: string;
  timestamp: number;
}

interface KeyResponse {
  session_key_encrypted: string;
  expires_in: number;
}

export const useKms = () => {
  const [kmsError, setKmsError] = useState<string | null>(null);
  const [sessionKey, setSessionKey] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);

  const requestSessionKey = async (payload: KeyRequestPayload): Promise<KeyResponse> => {
    const response = await fetch("http://localhost:8000/api/v1/kms/request-key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Failed to request session key");
    }

    return response.json();
  };

  const requestSessionKeyMutation = useMutation({
    mutationFn: requestSessionKey,
    onSuccess: (data) => {
      setSessionKey(data.session_key_encrypted);
      setExpiresIn(data.expires_in);
      setKmsError(null);
      console.log("Session Key success", data.session_key_encrypted);
      localStorage.setItem("session_key", data.session_key_encrypted);
      console.log("Session Key stored in localStorage", localStorage.getItem("session_key"));
    },
    onError: (err: Error) => {
      setKmsError(err.message);
    },
  });

  return {
    requestSessionKeyMutation,
    sessionKey,
    expiresIn,
    kmsError,
    resetKmsError: () => setKmsError(null),
  };
};
export default useKms;
export async function signMessageWithKey(privateKey: CryptoKey, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  try {
    const signature = await window.crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      privateKey,
      data
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  } catch (e) {
    console.error("❌ Signing failed. Is the privateKey valid?", privateKey);
    throw e;
  }
}

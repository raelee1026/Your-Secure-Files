import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { decryptPrivateKey } from "@/utils";

import {
  type Body_login_login_access_token as AccessToken,
  type ApiError,
  LoginService,
  type UserPublic,
  type UserRegister,
  UsersService,
} from "@/client";
import useKms, { signMessageWithKey } from "@/hooks/useKms";
import { handleError } from "@/utils";

interface TotpRequiredResponse {
  msg: string;
  email: string;
  requires_totp_setup: boolean; 
  //access_token: string;
  access_token?: string;
  totp_setup_token?: string;
}

interface TotpSetupResponse {
  qr_code_url: string;
}

const isLoggedIn = () => {
  return localStorage.getItem("access_token") !== null;
};

const useAuth = () => {
  const [error, setError] = useState<string | null>(null);
  const [requiresTotp, setRequiresTotp] = useState(false);
  const [email, setEmail] = useState<string | null>(null);
  //const [password, setPassword] = useState<string | null>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: user } = useQuery<UserPublic | null, Error>({
    queryKey: ["currentUser"],
    queryFn: UsersService.readUserMe,
    enabled: isLoggedIn(),
  });

  const { requestSessionKeyMutation } = useKms();
  const signUpMutation = useMutation({
    mutationFn: (data: UserRegister) =>
      UsersService.registerUser({ requestBody: data }),
    onSuccess: () => {
      navigate({ to: "/login" });
    },
    onError: (err: ApiError) => {
      handleError(err);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const login = async (data: AccessToken): Promise<TotpRequiredResponse> => {
    const response = await LoginService.loginAccessToken({
      formData: data,
    });
    const typedResponse = response as unknown as TotpRequiredResponse;

    if (typedResponse.requires_totp_setup && typedResponse.totp_setup_token) {
      localStorage.setItem("temp_token", typedResponse.totp_setup_token); // setup token
    } else if (typedResponse.access_token) {
      localStorage.setItem("access_token", typedResponse.access_token); // fallback or verify token
    }
    //localStorage.setItem("access_token", typedResponse.access_token);
    //console.log(`saveaccess token: ${typedResponse.access_token}`);
    return typedResponse;
  };

  const loginMutation = useMutation({
    mutationFn: login,
    onSuccess: (response: TotpRequiredResponse) => {
      setEmail(response.email || null);
      if (response.requires_totp_setup) {
        navigate({ to: "/totp-setup" });
      } else {
        setRequiresTotp(true);
      }
    },
    onError: (err: ApiError) => {
      setError(err.message);
    },
  });

  const setupTotp = async (): Promise<TotpSetupResponse> => {
    const response = await fetch("http://localhost:8000/api/v1/login/totp-setup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${localStorage.getItem("temp_token")}`,
      },
    });
    if (!response.ok) {
      throw new Error("Failed to setup TOTP");
    }
    return response.json() as Promise<TotpSetupResponse>;
  };
  
  const setupTotpMutation = useMutation({
    mutationFn: setupTotp,
    onSuccess: (data) => {
      // need to delete 
      console.log("TOTP setup successful:", data);
    },
    onError: (err: ApiError) => {
      setError(err.message);
    },
  });

  const totpVerify = async ({
    email,
    totp_code,
    password,
  }: {
    email: string;
    totp_code: string;
    password?: string;
  }) => {
    //console.log("decrypted name: ", email);
    console.log(password);
    localStorage.setItem("username", email);
    // localStorage.setItem("password", password);
    if (password !== undefined) {
      localStorage.setItem("password", password);
    }
    const response = await fetch("http://localhost:8000/api/v1/login/totp-verify", {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem("access_token")}`,
      },
      body: JSON.stringify({ email, totp_code }),
    });
    if (!response.ok) {
      throw new Error('TOTP verification failed');
    }
    return response.json() as Promise<{ access_token: string }>;
  };

  const totpVerifyMutation = useMutation({
    mutationFn: totpVerify,
    onSuccess: async (data, variables) => {
      localStorage.removeItem("temp_token");
      localStorage.setItem("access_token", data.access_token);
      setRequiresTotp(false);
      
      const username = variables.email;
      const timestamp = Math.floor(Date.now() / 1000);
      const rawPassword = variables.password;
      //console.log("rawPassword", rawPassword);

      if (username) {
        try {
          if (!rawPassword) throw new Error("Missing password for decrypting private key");
  
          const privateKey = await decryptPrivateKey(username, rawPassword);
          const message = `${username}:${timestamp}`;
          const signature_b64 = await signMessageWithKey(privateKey, message);
  
          requestSessionKeyMutation.mutateAsync(
            { username, signature_b64, timestamp },
            {
              onSuccess: (data) => {
                console.log("Session Key success", data.session_key_encrypted);
                localStorage.setItem("session_key", data.session_key_encrypted);
                
              },
              onError: (err) => {
                console.error("⚠️ Session Key fail:", err);
              }
            }
          );
        } catch (err) {
          console.error("Failed to request session key:", err);
        }
      }
  
      navigate({ to: "/" });
    },
    onError: (err: ApiError) => {
      setError(err.message);
    },
  });

  const logout = () => {
    localStorage.removeItem("access_token");
    navigate({ to: "/login" });
  };

  return {
    signUpMutation,
    loginMutation,
    totpVerifyMutation,
    setupTotpMutation,
    logout,
    user,
    requiresTotp,
    email,
    error,
    resetError: () => setError(null),
  };
};

export { isLoggedIn };
export default useAuth;
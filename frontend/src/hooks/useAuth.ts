import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import {
  type Body_login_login_access_token as AccessToken,
  type ApiError,
  LoginService,
  type UserPublic,
  type UserRegister,
  UsersService,
} from "@/client";
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
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: user } = useQuery<UserPublic | null, Error>({
    queryKey: ["currentUser"],
    queryFn: UsersService.readUserMe,
    enabled: isLoggedIn(),
  });

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

  const totpVerify = async ({ email, totp_code }: { email: string; totp_code: string }) => {
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
    onSuccess: (data) => {
      localStorage.removeItem("temp_token");
      localStorage.setItem("access_token", data.access_token);
      setRequiresTotp(false);
      setEmail(null);
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
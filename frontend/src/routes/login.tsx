import { Container, Image, Input, Text } from "@chakra-ui/react";
import {
  Link as RouterLink,
  createFileRoute,
  redirect,
} from "@tanstack/react-router";
import { type SubmitHandler, useForm } from "react-hook-form";
import { FiLock, FiMail, FiKey } from "react-icons/fi";

import type { Body_login_login_access_token as AccessToken } from "@/client";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { InputGroup } from "@/components/ui/input-group";
import { PasswordInput } from "@/components/ui/password-input";
import useAuth, { isLoggedIn } from "@/hooks/useAuth";
import Logo from "/assets/images/fastapi-logo.svg";
import { emailPattern, passwordRules } from "../utils";

export const Route = createFileRoute("/login")({
  component: Login,
  beforeLoad: async () => {
    if (isLoggedIn()) {
      throw redirect({
        to: "/",
      });
    }
  },
});

function Login() {
  const { loginMutation, totpVerifyMutation, requiresTotp, email, error, resetError } = useAuth();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<AccessToken & { totp_code?: string }>({
    mode: "onBlur",
    criteriaMode: "all",
    defaultValues: {
      username: "",
      password: "",
      totp_code: "",
    },
  });

  const onSubmit: SubmitHandler<AccessToken & { totp_code?: string }> = async (data) => {
    if (isSubmitting) return;

    resetError();
    try {
      if (!requiresTotp) {
        // first stage: login
        await loginMutation.mutateAsync(data);
        
      } else {
        // second stage: TOTP verification
        // console.log("totp verify!")
        if (!data.totp_code || !email) {
          throw new Error("TOTP code and email are required");
        }
        await totpVerifyMutation.mutateAsync({ email, totp_code: data.totp_code, password: data.password });
      }
    } catch (err) {
      console.error("Error:", err);
    }
  };

  return (
    <Container
      as="form"
      onSubmit={handleSubmit(onSubmit)}
      h="100vh"
      maxW="sm"
      alignItems="stretch"
      justifyContent="center"
      gap={4}
      centerContent
    >
      <Image
        src={Logo}
        alt="FastAPI logo"
        height="auto"
        maxW="2xs"
        alignSelf="center"
        mb={4}
      />
      {!requiresTotp ? (
        <>
          <Field
            invalid={!!errors.username}
            errorText={errors.username?.message || error}
          >
            <InputGroup w="100%" startElement={<FiMail />}>
              <Input
                id="username"
                {...register("username", {
                  required: "Username is required",
                  pattern: emailPattern,
                })}
                placeholder="Email"
                type="email"
              />
            </InputGroup>
          </Field>
          <PasswordInput
            type="password"
            startElement={<FiLock />}
            {...register("password", passwordRules())}
            placeholder="Password"
            errors={errors}
          />
          <RouterLink to="/recover-password" className="main-link">
            Forgot Password?
          </RouterLink>
        </>
      ) : (
        <Field
          invalid={!!errors.totp_code}
          errorText={errors.totp_code?.message || error}
        >
          <InputGroup w="100%" startElement={<FiKey />}>
            <Input
              id="totp_code"
              {...register("totp_code", {
                required: "TOTP code is required",
                minLength: { value: 6, message: "TOTP code must be 6 digits" },
                maxLength: { value: 6, message: "TOTP code must be 6 digits" },
              })}
              placeholder="Enter TOTP Code"
              type="text"
            />
          </InputGroup>
        </Field>
      )}
      <Button variant="solid" type="submit" loading={isSubmitting} size="md">
        {requiresTotp ? "Verify TOTP" : "Log In"}
      </Button>
      {!requiresTotp && (
        <Text>
          Don't have an account?{" "}
          <RouterLink to="/signup" className="main-link">
            Sign Up
          </RouterLink>
        </Text>
      )}
    </Container>
  );
}

export default Login;
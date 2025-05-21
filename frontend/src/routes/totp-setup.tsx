import { Container, Image, Text, Button, Box } from "@chakra-ui/react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import useAuth from "@/hooks/useAuth";
import Logo from "/assets/images/fastapi-logo.svg";

export const Route = createFileRoute("/totp-setup")({
  component: TotpSetup,
});

function TotpSetup() {
  const { setupTotpMutation } = useAuth();
  const navigate = useNavigate();

  return (
    <Container
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
      <Text>Setup TOTP for Two-Factor Authentication</Text>
      <Button
        variant="solid"
        onClick={() => setupTotpMutation.mutate()}
        loading={setupTotpMutation.isPending}
        mb={2}
      >
        Generate TOTP QR Code
      </Button>

      {setupTotpMutation.isSuccess && (
        <>
          <Text>Scan the QR code with your TOTP app (e.g., Google Authenticator):</Text>
          <Box my={4}>
            <img
              src={setupTotpMutation.data.qr_code_url}
              alt="TOTP QR Code"
              style={{ width: "200px", height: "200px" }}
            />
          </Box>
          <Text mb={2}>After scanning, return to the login page to enter your TOTP code.</Text>
          <Button
            colorScheme="teal"
            onClick={() => navigate({ to: "/login" })}
          >
            Back to Login
          </Button>
        </>
      )}

      {setupTotpMutation.isError && (
        <Text color="red.500">{setupTotpMutation.error.message}</Text>
      )}
    </Container>
  );
}

export default TotpSetup;
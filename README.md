# YoSpace

## Project Overview

**YoSpace** is a secure, end-to-end encrypted cloud storage system developed for the Cryptography Engineering Final Project. It ensures data confidentiality and authenticity by integrating AES-GCM encryption, RSA-based PKI, and TOTP-based two-factor authentication (2FA). All encryption is performed client-side, ensuring that plaintext data is never exposed to the server.

## Technical Overview

### Cryptography Features

* **Client-side Encryption**: All sensitive data is encrypted using AES-GCM directly in the browser.
* **RSA Key Pair**: Users generate RSA keys during registration. The private key is encrypted and stored locally (IndexedDB), and the public key is saved to the backend.
* **PKI Verification**: The server and KMS verify RSA signatures for authentication and key exchange.
* **Encrypted Session Key**: The KMS generates a session key encrypted with the user's public key, enabling symmetric encryption with AES-GCM.
* **2FA (TOTP)**: Time-based one-time passwords add an extra layer of user verification.

### System Architecture

| Component  | Technology                            |
| ---------- | ------------------------------------- |
| Frontend   | React + TypeScript + Vite + Chakra UI |
| Backend    | FastAPI (Python)                      |
| Database   | PostgreSQL                            |
| DevOps     | Docker Compose                        |
| Encryption | AES-GCM, RSA-OAEP                     |
| Auth       | JWT + TOTP (2FA)                      |

### Workflow Summary

1. **Registration**

   * Generates RSA key pair
   * Encrypts and stores private key in browser (IndexedDB)
   * Sends public key to server

2. **Login**

   * User authenticates with password and TOTP
   * Sends a signed message with the RSA private key
   * Server verifies signature and requests session key from KMS
   * KMS returns AES session key encrypted with RSA public key

3. **Data Encryption and Storage**

   * Frontend encrypts data using AES-GCM with session key
   * Encrypted data is sent to backend and stored in database
   * Metadata is preserved alongside ciphertext

4. **Data Retrieval**

   * Backend returns ciphertext and metadata
   * Frontend decrypts data using AES session key

## Demo

[Watch the Demo on YouTube](https://youtu.be/ADBPWY2R5ak?si=JQzMLovUa9lPVkst)

## Getting Started

### Prerequisites

* Python 3.9+
* Node.js 14+
* Docker & Docker Compose

### Installation

**Clone the Repository**

   ```bash
   git clone https://github.com/raelee1026/Your-Secure-Files.git
   cd Your-Secure-Files
   ```
#### Docker
1. **Frontend Setup**

   ```bash
   cd ../frontend
   npm install
   npm run build
   ```
2. **Start with Docker Compose**
   ```bash
   docker compose build
   docker compose watch
   ```
3. **Debug Logs**
   ```bash
   docker compose logs backend
   docker compose logs frontend
   ```
#### Local Development
1. **Backend Setup**

   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```

2. **Frontend Setup**

   ```bash
   cd ../frontend
   npm install
   npm run build
   npm run dev
   ```

## Testing

To run backend tests:

```bash
cd backend
pytest
```

To test frontend (if applicable):

```bash
cd frontend
npm test
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.


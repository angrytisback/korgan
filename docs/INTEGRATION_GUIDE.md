# Korgan Developer Integration Guide

Enterprise integration manual for **Korgan (`korgan`)**, an RFC-compliant Identity & Access Management (IAM) engine written in Rust.

---

## 1. Architectural Integration Models

Korgan supports three distinct client consumption paradigms:

1. **Web Single-Page Applications (SPAs) & SSR Applications**: Fully automated, XSS-resilient session management using strict `__Host-` prefixed, `HttpOnly`, `SameSite=Strict` cookies.
2. **Mobile Apps (iOS/Android) & Command-Line Interfaces (CLIs)**: Pure JSON transport with explicit Bearer token handling and storage in secure enclaves (e.g., iOS Keychain, Android Keystore).
3. **Real-time Gateway Services (WebSocket / WebRTC Signaling)**: Zero-overhead, ephemeral single-use tickets designed to authenticate streaming connections without exposing long-lived credentials over query strings.

```
                      +-----------------------------+
                      |       Client Platform       |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         | (Web Browser)             | (Mobile / Native CLI)     | (Real-time Gateway)
         v                           v                           v
  [__Host- Cookie]             [Bearer Tokens]             [Ephemeral WS Ticket]
  - Secure, HttpOnly          - Authorization: Bearer     - 15s expiration
  - SameSite=Strict           - Stored in Keychain/Keystore - Atomic GETDEL consumption
  - Zero JS exposure          - Explicit body refresh     - Bypass DB roundtrips
         |                           |                           |
         +---------------------------+---------------------------+
                                     |
                                     v
                        +-------------------------+
                        |      Korgan Engine      |
                        |      (Axum 0.8)         |
                        +-------------------------+
```

---

## 2. Web Integration (Strict Cookie Mode)

### 2.1 The `X-Client-Type: web` Contract
When the client passes the `X-Client-Type: web` request header (or lowercase/uppercase equivalents):
- Korgan issues tokens as `Set-Cookie` response headers:
  - `access_token`: Short-lived (15 minutes), `Path=/; Secure; HttpOnly; SameSite=Strict`.
  - `__Host-refresh_token`: Long-lived (30 days), `Path=/; Secure; HttpOnly; SameSite=Strict`.
- The JSON response payload will also contain token values for backwards compatibility, but web applications **must rely exclusively on cookies** to prevent XSS-based token theft.

### 2.2 Primary Login Flow
```http
POST /api/v1/auth/login HTTP/1.1
Host: auth.example.com
Content-Type: application/json
X-Client-Type: web

{
  "email": "user@example.com",
  "password": "CorrectHorseBatteryStaple123!"
}
```

**Response (`200 OK`):**
```http
HTTP/1.1 200 OK
Set-Cookie: access_token=eyJhbGciOiJFZERTQSI...; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900
Set-Cookie: __Host-refresh_token=0192a8f0...; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000
Content-Type: application/json

{
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f"
}
```

### 2.3 Transparent Token Refresh
Because `credentials: "include"` in `fetch` automatically transmits cookies, a web client refreshes sessions with an empty JSON body or no payload:

```javascript
// Web frontend token refresh
const response = await fetch("https://auth.example.com/api/v1/auth/refresh", {
  method: "POST",
  headers: {
    "X-Client-Type": "web"
  },
  credentials: "include"
});

if (!response.ok) {
  // Session expired or revoked; redirect to login
  window.location.href = "/login";
}
```

> [WARNING] **CRITICAL ANTI-PATTERN**: Never send `refresh_token` in the JSON body when using `X-Client-Type: web`. Submitting tokens in both cookie and JSON body triggers HTTP `422 Unprocessable Entity` (Ambiguous Token Injection).

---

## 3. Mobile & Native CLI Integration (Bearer Token Mode)

Native applications running on mobile or desktop environments must not use cookies, as cookie jars in non-browser environments lack native CSRF protections and standard domain sandboxing.

### 3.1 The `X-Client-Type: mobile` or `X-Client-Type: cli` Contract
- Korgan will **not** set cookies on responses.
- The client receives `access_token` and `refresh_token` directly in the JSON response payload.
- All authenticated API requests require the standard `Authorization: Bearer <access_token>` header.
- Token refresh requires transmitting the `refresh_token` inside the JSON body.

### 3.2 Primary Login Flow
```http
POST /api/v1/auth/login HTTP/1.1
Host: auth.example.com
Content-Type: application/json
X-Client-Type: mobile

{
  "email": "engineer@example.com",
  "password": "CorrectHorseBatteryStaple123!"
}
```

**Response (`200 OK`):**
```json
{
  "access_token": "eyJhbGciOiJFZERTQSI...",
  "refresh_token": "0192a8f07c1b700080001a2b3c4d5e6f...",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f"
}
```

### 3.3 Token Rotation Call
```http
POST /api/v1/auth/refresh HTTP/1.1
Host: auth.example.com
Content-Type: application/json
X-Client-Type: mobile

{
  "refresh_token": "0192a8f07c1b700080001a2b3c4d5e6f..."
}
```

**Response (`200 OK`):**
```json
{
  "access_token": "eyJhbGciOiJFZERTQSI...",
  "refresh_token": "0192a8f3524b700080009876543210ab...",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f"
}
```

Store the newly issued `refresh_token` immediately in your secure key vault and overwrite the previous one.

---

## 4. Real-time Gateway Integration (WebSocket Tickets)

WebSocket connections do not support custom request headers during browser-initiated handshakes (`new WebSocket(url)`). Transmitting long-lived JWTs or refresh tokens in URL query strings exposes credentials to proxy logs, browser histories, and referrer leaks.

Korgan solves this with **RFC-compliant, ephemeral WebSocket tickets**:
1. Client requests an ephemeral ticket via HTTP POST using its active Bearer token.
2. Korgan returns a cryptographically random, 15-second ticket stored in Redis.
3. Client initiates the WebSocket handshake supplying the ticket in query or subprotocol (`ws://gateway?ticket=<TICKET>`).
4. The Gateway verifies and consumes the ticket against Korgan via atomic `GETDEL`.

```
[Client]                      [Korgan Auth]              [Real-time Gateway]
   |                                |                             |
   | 1. POST /api/v1/auth/ws-ticket |                             |
   |    (Bearer Access Token)       |                             |
   |------------------------------->|                             |
   |                                |                             |
   | 2. { "ticket": "...", "ttl":15}|                             |
   |<-------------------------------|                             |
   |                                                              |
   | 3. ws://gateway?ticket=<TICKET>                              |
   |------------------------------------------------------------->|
   |                                                              |
   |                                | 4. POST /ws-ticket/verify   |
   |                                |    { "ticket": "..." }      |
   |                                |<----------------------------|
   |                                |                             |
   |                                | 5. 200 OK (User & Session)  |
   |                                |    Atomic GETDEL consumed   |
   |                                |---------------------------->|
   |                                                              |
   | 6. WebSocket Connection Established                          |
   |<============================================================>|
```

### 4.1 Step 1: Issue Ticket (Client -> Korgan)
```http
POST /api/v1/auth/ws-ticket HTTP/1.1
Host: auth.example.com
Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json
```

**Response (`200 OK`):**
```json
{
  "ticket": "8f3b9a102c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
  "expires_in": 15
}
```

### 4.2 Step 2: Establish Real-time Connection (Client -> Gateway)
```javascript
const ws = new WebSocket(`wss://gateway.example.com/ws?ticket=${ticketData.ticket}`);
```

### 4.3 Step 3: Verify Ticket (Gateway -> Korgan)
Your internal gateway (Node.js, Go, Rust, Python) verifies the ticket immediately:

```http
POST /api/v1/auth/ws-ticket/verify HTTP/1.1
Host: auth.internal:8080
Content-Type: application/json

{
  "ticket": "8f3b9a102c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
}
```

**Response (`200 OK`):**
```json
{
  "sub": "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f",
  "sid": "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f",
  "role": "user"
}
```

**Security Guarantees:**
- **Atomic Single-Use**: Consumed immediately via Valkey/Redis `GETDEL`. Any second attempt returns `401 Unauthorized`.
- **Instant Revocation Check**: Rejects tickets if the underlying user session has been revoked or blacklisted in Redis.
- **Tight TTL**: Hard 15-second expiration limits exposure window.

---

## 5. Offline JWKS Verification for Peripheral Microservices

Downstream services in your microservice mesh can verify Korgan JWT access tokens locally with zero database roundtrips by fetching public keys from the JWKS endpoint:

`GET /.well-known/jwks.json`

### Example JWKS Output:
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "korgan-2026-v1",
      "x": "IFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3M",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

### Verification Rules:
1. Cache the JWKS response with a 1-hour TTL.
2. Validate the JWT header: `alg` must be `EdDSA` and `crv` must be `Ed25519`.
3. Assert that `iss` matches `https://auth.example.com` and `aud` contains `korgan` (or configured client audiences).
4. Assert that `exp > current_timestamp`.
5. Check if the session ID (`sid`) is listed in your shared Redis blacklist (`blacklist:session:<sid>`) for immediate revocation enforcement.

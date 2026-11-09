# Korgan Operational Failure & Troubleshooting Guide

Exhaustive diagnostic and failure-resolution guide for **Korgan (`korgan`)**. This guide is formatted in strict accordance with the **"Symptom / Error Code" -> "Root Cause" -> "Immediate Solution (Code/Config Snippet)"** paradigm.

---

## Index of Operational Incidents

1. [422 Unprocessable Entity (`VALIDATION_FAILED`): Ambiguous Refresh Token Injection](#1-422-unprocessable-entity-ambiguous-refresh-token-injection)
2. [403 Forbidden (`AUTH_FORBIDDEN` / `AUTH_STEP_UP_REQUIRED`): Step-Up Authentication Required](#2-403-forbidden-auth_forbidden--auth_step_up_required-step-up-authentication-required)
3. [401 Unauthorized (`AUTH_UNAUTHORIZED` / `AUTH_WS_TICKET_EXPIRED`): WebSocket Ticket Rejection](#3-401-unauthorized-auth_unauthorized--auth_ws_ticket_expired-websocket-ticket-rejection)
4. [Silent Cookie Dropping (`SameSite=Strict`): Cross-Site / Reverse Proxy Session Loss](#4-silent-cookie-dropping-samesitestrict-in-reverse-proxy)
5. [401 Unauthorized (`AUTH_TOKEN_INVALID`): Clock Skew in Distributed JWT Validation](#5-401-unauthorized-clock-skew-in-jwt-validation)
6. [503 Service Unavailable (`SERVICE_UNAVAILABLE`): Rate Limiter Fail-Closed Mode](#6-503-service-unavailable-rate-limiter-fail-closed-on-redis-outage)
7. [409 Conflict (`AUTH_CONFLICT`): Email Already Exists](#7-409-conflict-email-or-username-collision)
8. [401 Unauthorized (`AUTH_TOKEN_REUSE_DETECTED`): Token Family Compromise Incident](#8-401-unauthorized-refresh-token-family-compromise)

---

## 1. 422 Unprocessable Entity: Ambiguous Refresh Token Injection

### Symptom / Error Code
The client receives HTTP `422 Unprocessable Entity` with `Content-Type: application/problem+json` upon calling `/api/v1/auth/refresh` or `/api/v1/auth/logout`:

```json
{
  "type": "https://errors.korgan.dev/validation/failed",
  "title": "Validation Failed",
  "status": 422,
  "detail": "Validation error: refresh_token: ambiguous token: token provided in both cookie and JSON body",
  "instance": "urn:uuid:0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f",
  "code": "VALIDATION_FAILED",
  "errors": [
    {
      "field": "refresh_token",
      "reason": "ambiguous token: token provided in both cookie and JSON body"
    }
  ]
}
```

### Root Cause
Korgan implements strict dual-mode channel separation to prevent injection attacks and browser state desynchronization. If a client transmits a refresh token in **both** the HTTP Cookie (`__Host-refresh_token` or `refresh_token`) **and** the JSON request body (`{"refresh_token": "..."}`), Korgan aborts the operation immediately as an ambiguous injection attempt.

### Immediate Solution

**For Web Applications (`X-Client-Type: web`):**
Send cookies only. Do not populate the request body:
```javascript
// Fix: Provide empty body or omit body completely
await fetch("https://auth.example.com/api/v1/auth/refresh", {
  method: "POST",
  headers: {
    "X-Client-Type": "web"
  },
  credentials: "include"
});
```

**For Mobile / CLI Applications (`X-Client-Type: mobile` or `X-Client-Type: cli`):**
Do not pass Cookie headers. Provide the refresh token exclusively in the JSON payload:
```bash
curl -X POST https://auth.example.com/api/v1/auth/refresh \
  -H "X-Client-Type: mobile" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "0192a8f07c1b700080001a2b3c4d5e6f..."}'
```

---

## 2. 403 Forbidden (`AUTH_FORBIDDEN` / `AUTH_STEP_UP_REQUIRED`): Step-Up Authentication Required

### Symptom / Error Code
A user attempting sensitive account operations (e.g. `POST /api/v1/password/change`, `DELETE /api/v1/sessions`, or `POST /api/v1/auth/passkeys/register/start`) receives HTTP `403 Forbidden` (`AUTH_FORBIDDEN` / `AUTH_STEP_UP_REQUIRED`):

```json
{
  "type": "https://errors.korgan.dev/auth/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "recent re-authentication required: auth_time older than 15 minutes",
  "instance": "urn:uuid:0192a8f1-8a2c-7000-8000-2b3c4d5e6f7a",
  "code": "AUTH_FORBIDDEN"
}
```
Or:
```json
{
  "type": "https://errors.korgan.dev/auth/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "step-up authentication required: token must have 'mfa' or 'passkey' amr claim",
  "instance": "urn:uuid:0192a8f1-8a2c-7000-8000-2b3c4d5e6f7a",
  "code": "AUTH_FORBIDDEN"
}
```
*(Note: In API integration documentation and SDK client taxonomy, this condition is also referred to as `AUTH_STEP_UP_REQUIRED`).*

### Root Cause
1. **Stale `auth_time`**: The user logged in more than 15 minutes (900 seconds) ago. Even if access tokens were continuously refreshed, RFC 7519 / OIDC `auth_time` preserves the initial login timestamp across token family rotations.
2. **Missing AMR Claim**: The user has enrolled TOTP MFA or a FIDO2 Passkey, but is presenting a token created solely with password authentication (`amr: ["pwd"]`).

### Immediate Solution
Prompt the user to perform interactive step-up verification before calling sensitive endpoints:

```typescript
async function executeSensitiveAction(actionFn: () => Promise<Response>) {
  let res = await actionFn();
  if (res.status === 403) {
    const error = await res.json();
    if (error.detail?.includes("step-up") || error.detail?.includes("recent re-authentication")) {
      // Prompt user to re-authenticate with TOTP or biometric Passkey
      await triggerMfaOrPasskeyReauthModal();
      // Retry action with the fresh access token
      res = await actionFn();
    }
  }
  return res;
}
```

---

## 3. 401 Unauthorized (`AUTH_UNAUTHORIZED` / `AUTH_WS_TICKET_EXPIRED`): WebSocket Ticket Rejection

### Symptom / Error Code
The real-time gateway or microservice receives HTTP `401 Unauthorized` (`AUTH_UNAUTHORIZED` / `AUTH_WS_TICKET_EXPIRED`) when verifying a client's WebSocket ticket (`POST /api/v1/auth/ws-ticket/verify`):

```json
{
  "type": "https://errors.korgan.dev/auth/unauthorized",
  "title": "Unauthorized",
  "status": 401,
  "detail": "invalid or expired websocket ticket",
  "instance": "urn:uuid:0192a8f2-9b3d-7000-8000-3c4d5e6f7a8b",
  "code": "AUTH_UNAUTHORIZED"
}
```
*(Note: In event gateway and monitoring telemetry, this condition is classified under `AUTH_WS_TICKET_EXPIRED`).*

### Root Cause
1. **Ticket Expiration**: The client took longer than 15 seconds between obtaining the ticket (`POST /api/v1/auth/ws-ticket`) and initiating the WebSocket connection.
2. **Ticket Replay / Double Consumption**: The gateway or client sent multiple verification requests for the same ticket. Tickets are consumed atomically via Redis `GETDEL`.
3. **Session Revocation**: The user's underlying session was revoked or banned before connection establishment.

### Immediate Solution
1. Ensure the frontend requests the ticket immediately before opening the WebSocket socket:
   ```javascript
   // Anti-pattern: Pre-fetching tickets at page load
   // Recommended pattern: Just-in-Time ticket issuance
   async function connectWebSocket() {
     const ticketRes = await fetch("/api/v1/auth/ws-ticket", {
       method: "POST",
       headers: { Authorization: `Bearer ${getAccessToken()}` }
     });
     const { ticket } = await ticketRes.json();
     
     // Connect immediately
     const ws = new WebSocket(`wss://gateway.example.com/ws?ticket=${ticket}`);
   }
   ```
2. In the Gateway, verify the ticket exactly once during the connection handshake and discard it.

---

## 4. Silent Cookie Dropping (`SameSite=Strict`) in Reverse Proxy

### Symptom
Web users log in successfully (`200 OK`), but subsequent requests to authenticated endpoints return `401 Unauthorized`. Browser developer tools show that cookies were issued but are not attached to subsequent requests.

### Root Cause
1. **Cross-Origin Deployment**: Frontend is on `app.example.com` while Korgan API is on `api.example.com` without proper site-level cookie scoping. `SameSite=Strict` drops cookies during cross-site navigations.
2. **Reverse Proxy Stripping Protocol Headers**: Korgan marks cookies with the `Secure` flag. When running behind an SSL-terminating reverse proxy (Nginx, Envoy, Cloudflare), if the proxy fails to pass `X-Forwarded-Proto: https`, Axum treats the connection as insecure HTTP and browser rejects `__Host-` cookies.
3. **Missing `__Host-` Prefix Invariants**: RFC 6265bis mandates that `__Host-` cookies must have `Secure; Path=/` and must omit the `Domain` attribute.

### Immediate Solution
Configure your reverse proxy (Nginx) to forward protocol headers and match trusted proxy CIDRs:

```nginx
# /etc/nginx/conf.d/korgan.conf
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    
    # Preserve original client protocol and IP
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https; # Enforce HTTPS indicator
}
```

And in `config/default.toml` or environment:
```toml
[server]
public_base_url = "https://iam.example.com"
cors_allowed_origins = ["https://app.example.com"]
```

---

## 5. 401 Unauthorized: Clock Skew in JWT Validation

### Symptom / Error Code
Microservices verifying Korgan access tokens intermittently reject valid tokens immediately after login with `token used before issued` or `token expired`.

### Root Cause
Network Time Protocol (NTP) desynchronization across distributed server nodes. If a gateway node's clock runs slightly behind or ahead of Korgan's clock, JWT timestamp assertions (`iat`, `nbf`, `exp`) will fail unless a clock skew margin is configured.

### Immediate Solution
1. Korgan includes a built-in **30-second NTP clock skew tolerance** in token verification and Step-Up authentication.
2. In downstream microservices validating Korgan JWTs, configure a 30-to-60-second leeway in your JWT validator:

```rust
// In Rust jsonwebtoken / biscuit validator:
let mut validation = Validation::new(Algorithm::EdDSA);
validation.leeway = 30; // 30 seconds clock skew tolerance
```
```javascript
// In Node.js jsonwebtoken / jose:
jwt.verify(token, publicKey, {
  algorithms: ['EdDSA'],
  clockTolerance: 30 // 30 seconds leeway
});
```

---

## 6. 503 Service Unavailable: Rate Limiter Fail-Closed on Redis Outage

### Symptom / Error Code
All API requests immediately fail with HTTP `503 Service Unavailable`:

```json
{
  "type": "https://errors.korgan.dev/system/service-unavailable",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "cache storage error: redis connection timed out",
  "instance": "urn:uuid:0192a8f3-aa4e-7000-8000-4d5e6f7a8b9c",
  "code": "SERVICE_UNAVAILABLE"
}
```

### Root Cause
**Fail-Closed Security Design**: Korgan's sliding-window rate limiter treats Redis network partitions as an existential denial-of-service or brute-force threat. To protect cryptographic primitives (Argon2id hashing) and prevent brute-force attacks during Redis unavailability, the rate-limiter layer fails **closed** by default (`fail_closed = true`).

### Immediate Solution
1. Check Redis / Valkey container health:
   ```bash
   docker compose ps redis
   docker compose logs --tail 50 redis
   ```
2. Verify Redis connectivity from the host:
   ```bash
   redis-cli -u redis://localhost:6379 PING
   # Expected response: PONG
   ```
3. If running in a staging or development environment where high availability is not required, ensure Redis memory limits and max connection pools are tuned:
   ```dotenv
   REDIS_URL=redis://localhost:6379
   ```

---

## 7. 409 Conflict: Email or Username Collision

### Symptom / Error Code
HTTP `409 Conflict` during user registration:

```json
{
  "type": "https://errors.korgan.dev/auth/conflict",
  "title": "Conflict",
  "status": 409,
  "detail": "email already exists",
  "instance": "urn:uuid:0192a8f4-bb5f-7000-8000-5e6f7a8b9c0d",
  "code": "AUTH_CONFLICT"
}
```

### Root Cause
1. **RFC-Compliant Normalization**: Korgan silently normalizes all emails to trimmed lowercase. E.g., `User@Example.Com` and `user@example.com` map to the identical unique identity index.
2. **Unicode NFC Username Normalization**: Usernames undergo Unicode NFC canonical normalization to prevent visually deceptive spoofing attacks.

### Immediate Solution
Prompt the user to sign in or initiate the password recovery flow via `/api/v1/password/forgot`.

---

## 8. 401 Unauthorized: Refresh Token Family Compromise

### Symptom / Error Code
A user is unexpectedly logged out across all devices and receives:

```json
{
  "type": "https://errors.korgan.dev/auth/token-reuse-detected",
  "title": "Refresh Token Reuse Detected",
  "status": 401,
  "detail": "The provided refresh token has already been rotated. For your security, the entire session family has been revoked.",
  "instance": "urn:uuid:0192a8f5-cc6a-7000-8000-6f7a8b9c0d1e",
  "code": "AUTH_TOKEN_REUSE_DETECTED"
}
```

### Root Cause
An attacker or misconfigured client presented an older, already rotated refresh token. Under RFC 6749 Section 10.4 guidelines, Korgan treats refresh token reuse as evidence of token compromise and automatically executes cascading revocation of the entire `token_family_id`.

### Immediate Solution
1. The user must log in again to establish a fresh session and token family.
2. Audit the client implementation to ensure it does not execute parallel, un-debounced refresh calls:
   ```typescript
   // Use a promise lock to prevent concurrent refresh requests
   let activeRefreshPromise: Promise<string> | null = null;
   
   async function getFreshToken(): Promise<string> {
     if (!activeRefreshPromise) {
       activeRefreshPromise = executeTokenRefresh().finally(() => {
         activeRefreshPromise = null;
       });
     }
     return activeRefreshPromise;
   }
   ```

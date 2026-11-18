# ARCHITECTURE.md — System Architecture & Cryptographic Data Flow

Korgan is engineered as a standalone, high-throughput Identity and Access Management (IAM) core. It combines stateless asymmetric token verification for downstream microservices with stateful, centrally revocable session families.

---

## 1. Deployment Topologies

Korgan supports two primary production deployment models without code changes:

### A. Single-Node Self-Hosted (Standalone / Edge)
* **Topology:** Single Korgan `distroless` container (`< 15 MB` static binary) paired with local PostgreSQL 16+ and Redis 7+ instances behind a TLS-terminating reverse proxy (Nginx / Caddy / Cloudflare Tunnel).
* **Characteristics:** Sub-20MB idle RAM footprint, instant cold start, embedded SQLx database migrations executed automatically at boot.

### B. High-Availability Distributed Cluster (Enterprise / Multi-Service)
* **Topology:** Horizontally scaled stateless Korgan API pods behind an L7 Load Balancer, connected to a Primary/Replica PostgreSQL cluster and a Redis Sentinel/Cluster setup.
* **Characteristics:**
  * Downstream microservices verify Ed25519 Access Tokens locally using public keys fetched from `GET /.well-known/jwks.json` with zero network hops to Korgan.
  * Global session revocation and rate limiting synchronize instantaneously across all nodes via Redis.

---

## 2. Domain Model & Hexagonal Layer Topology

```text
+-----------------------------------------------------------------------+
|                        INBOUND ADAPTERS                               |
|   Axum HTTP Router  |  Extractors (Auth/Admin/StepUp)  |  Clap CLI    |
+-----------------------------------+-----------------------------------+
                                    | DTOs & Value Objects
                                    v
+-----------------------------------------------------------------------+
|                       APPLICATION LAYER                               |
|   Use Cases (Auth, OAuth, Passkeys, MFA, Admin)  |  EventBus Workers  |
+-----------------------------------+-----------------------------------+
                                    | Trait Interfaces (Ports)
                                    v
+-----------------------------------------------------------------------+
|                          DOMAIN CORE                                  |
|   Entities (User, Session, AuditLog, Passkey)  |  Value Objects       |
+-----------------------------------+-----------------------------------+
                                    ^ Implemented By
                                    |
+-----------------------------------------------------------------------+
|                       OUTBOUND ADAPTERS                               |
|   SQLx Postgres  |  Deadpool Redis  |  Ed25519/Argon2  |  SMTP/HIBP   |
+-----------------------------------------------------------------------+

# Korgan Production Infrastructure & Disaster Recovery Guide

This document outlines the production deployment hardening, telemetry isolation, and PostgreSQL 17 Continuous Archiving and Point-In-Time-Recovery (PITR) strategy for Korgan.

---

## 1. Nginx Hardening & Zero-Trust Reverse Proxy Architecture

The production reverse proxy configuration is located at `config/nginx/korgan.conf`.

### 1.1 Cloudflare Real IP Restoration & Perimeter Security
- **Cloudflare Edge Validation**: The proxy trusts only Cloudflare IPv4 and IPv6 CIDR blocks, as well as designated internal networks.
- **Header Parsing**: `real_ip_header CF-Connecting-IP;` and `real_ip_recursive on;` ensure `$remote_addr` correctly reflects the genuine client IP address for rate limiting and audit logging.

### 1.2 Strict TLS 1.3 & Zero-Trust Security Headers
- **TLS 1.3 Exclusive**: `ssl_protocols TLSv1.3; ssl_prefer_server_ciphers off;` disables legacy TLS versions (TLS 1.0, 1.1, 1.2) and avoids cipher downgrade attacks.
- **HSTS with Preload**: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` enforces 2-year HTTPS pin.
- **Zero-Trust Headers**: Enforces strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and restrictive `Permissions-Policy`.

### 1.3 Adaptive Rate Limiting
- **Authentication Limiting**: Keyed by client IP (`$binary_remote_addr`) with a limit of 10 requests/minute (burst 5, `nodelay`) on `/api/v1/auth/login`, `/api/v1/auth/register`, and `/api/v1/auth/ws-ticket`.
- **API Limiting**: 100 requests/minute for general API endpoints.

### 1.4 Prometheus Telemetry & Gateway Isolation
- **`/metrics` Route**: Bound to Prometheus scrape format. External access is forbidden (`deny all;`). Only trusted internal networks (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are permitted.
- **`/api/v1/auth/ws-ticket/verify`**: Restricted to internal microservices and WebRTC/WebSocket gateway servers.

### 1.5 WebSocket Upgrade Protocol
- Uses HTTP/1.1 connection upgrades:
  ```nginx
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection $connection_upgrade;
  ```

---

## 2. PostgreSQL 17 Continuous Archiving & PITR Strategy

Korgan relies on PostgreSQL 17 as its primary source of truth, enforcing cryptographically chained audit logs, user identities, sessions, and passkey credentials.

### 2.1 Objectives & Service Level Indicators
- **RPO (Recovery Point Objective)**: **< 1 minute** (maximum data loss window via continuous WAL streaming/archiving).
- **RTO (Recovery Time Objective)**: **< 15 minutes** (duration from disaster declaration to restored service).

---

### 2.2 PostgreSQL 17 Server Configuration (`postgresql.conf`)

Due to the immutable append-only nature of the `audit_logs` table, continuous archiving at the Write-Ahead Logging (WAL) level is enforced:

```ini
# Replication & Continuous Archiving
wal_level = replica
archive_mode = on
archive_command = 'test ! -f /mnt/wal_archive/%f && cp %p /mnt/wal_archive/%f'
archive_timeout = 300               # Forces WAL switch every 300 seconds (5 mins)

# WAL Segment Sizing & Checkpoints
max_wal_size = 16GB
min_wal_size = 2GB
checkpoint_completion_target = 0.9
wal_compression = zstd               # PostgreSQL 17 native zstd WAL compression
```

---

### 2.3 pgBackRest Configuration (`/etc/pgbackrest/pgbackrest.conf`)

Store backups in dedicated object storage (AWS S3, Cloudflare R2, or private MinIO):

```ini
[global]
repo1-type=s3
repo1-s3-endpoint=s3.eu-central-1.amazonaws.com
repo1-s3-bucket=korgan-db-backups
repo1-s3-region=eu-central-1
repo1-s3-key=ENV:PG_S3_KEY
repo1-s3-key-secret=ENV:PG_S3_SECRET
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=ENV:PG_CIPHER_PASSPHRASE
repo1-retention-full=4               # Keep 4 full weekly backups
repo1-retention-diff=14              # Keep 14 daily differential backups
process-max=4
compress-type=zstd
compress-level=6

[korgan]
pg1-path=/var/lib/postgresql/17/main
pg1-user=postgres
```

### 2.4 Backup Schedule
- **Full Base Backup**: Weekly (Sundays at 02:00 UTC):
  ```bash
  pgbackrest --stanza=korgan --type=full backup
  ```
- **Differential Backup**: Daily (Monday-Saturday at 02:00 UTC):
  ```bash
  pgbackrest --stanza=korgan --type=diff backup
  ```
- **Continuous WAL Archiving**: Ongoing every `archive_timeout` (300s / 5 mins) or upon reaching 16MB WAL segment boundary.

---

### 2.5 Cryptographic Integrity Verification: Automated Daily Cron

Every day, an automated cron job runs `korgan audit verify` to mathematically confirm the cryptographic chain integrity over all recorded logs. If a broken hash or tampered entry is detected, it alerts the security team immediately:

```cron
# /etc/cron.d/korgan-audit-verify
# Runs daily at 03:00 UTC to verify audit chain integrity
0 3 * * * root /usr/local/bin/korgan audit verify || /usr/local/bin/notify_security "CRITICAL: Korgan audit chain integrity verification failed!"
```

---

### 2.6 Disaster Recovery: Step-by-Step PITR Runbook

When human error, data tampering, or infrastructure failure occurs (e.g. corruption detected by `korgan audit verify` at `2026-11-02 14:35:22 UTC`), follow this procedure to restore database state to the exact second prior to the incident:

#### Step 1: Stop Application & Isolate Cluster
```bash
# Terminate Korgan services
systemctl stop korgan.service

# Stop PostgreSQL instance
systemctl stop postgresql@17-main.service
```

#### Step 2: Backup Existing State & Clean Data Directory
```bash
# Move corrupted data directory aside for forensic audit
mv /var/lib/postgresql/17/main /var/lib/postgresql/17/main_corrupted_$(date +%s)
install -d -m 0700 -o postgres -g postgres /var/lib/postgresql/17/main
```

#### Step 3: Restore Base Backup & Target Recovery Time
Execute `pgbackrest restore` as the `postgres` user targeting the timestamp before the corruption:

```bash
sudo -u postgres pgbackrest --stanza=korgan \
    --type=time \
    --target="2026-11-02 14:35:00 UTC" \
    --target-action=promote \
    restore
```

This restores the closest base/diff backup and configures PostgreSQL 17 recovery settings automatically:
- Creates `standby.signal` or writes recovery directives.
- In PostgreSQL 17, `recovery_target_time = '2026-11-02 14:35:00 UTC'` and `recovery_target_action = 'promote'`.

#### Step 4: Start PostgreSQL 17 in Recovery Mode
```bash
systemctl start postgresql@17-main.service
```
Monitor recovery replay via logs:
```bash
tail -f /var/log/postgresql/postgresql-17-main.log
# Look for: "recovery stopping at restore point / timestamp", followed by "database system was not properly shut down; automatic recovery in progress" and "database system is ready to accept connections".
```

#### Step 5: Verify Audit Log Cryptographic Integrity
Run Korgan CLI to verify the restored database chain:
```bash
korgan audit verify
```
Expected output:
```
Audit log cryptographic chain is valid. Total verified records: <COUNT>.
```

#### Step 6: Start Application Server
```bash
systemctl start korgan.service
curl -f http://127.0.0.1:8080/health/ready
```
Recovery is complete.

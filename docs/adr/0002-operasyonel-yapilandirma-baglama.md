# ADR 0002 — Havuz, worker ve login ayarlarının gerçekten uygulanması

Durum: Kabul edildi · Kusurlar: A-04, A-07, A-15 (kısmen)

## Bağlam
`database.min_connections`, `acquire_timeout_secs`, `idle_timeout_secs`, `redis.pool_size`, `connect_timeout_secs` doğrulanıyordu ama hiçbir yerde uygulanmıyordu; havuzlar kütüphane varsayılanlarıyla (30 sn acquire bekleme, Redis'te sınırsız bekleme) çalışıyordu. GC aralığı/batch/saklama süresi, drain süresi, kuyruk kapasitesi ve login IP bütçesi kod içine gömülüydü. `rate_limit.login_max_requests` ve `window_secs` login yoluna bağlı değildi.

## Karar
- Postgres havuzu tüm anahtarları uygular ve her bağlantıda sunucu tarafı `statement_timeout` ayarlar (`database.statement_timeout_secs`, varsayılan 15 sn, `0` = kapalı).
- Redis havuzu `pool_size` ve `connect_timeout_secs` (wait/create/recycle) ile sınırlanır; zaman aşımı mevcut fail-closed davranışıyla 503'e döner.
- Yeni `[workers]` bölümü: `event_queue_capacity`, `gc_interval_secs`, `gc_batch_size`, `unverified_retention_secs`, `shutdown_drain_secs`. Varsayılanlar eski sabitlerle aynıdır; `#[serde(default)]` sayesinde eski config dosyaları çalışmaya devam eder.
- Login IP bütçesi `rate_limit.login_max_requests` / `window_secs` değerlerinden gelir (varsayılan 10 / 60 sn, değişmedi).

## Sonuçlar
- (+) Belgelenen her anahtar gerçekten bir şey yapar; yanlış güvenlik varsayımı kalmaz.
- (−) Davranış değişikliği: `statement_timeout` varsayılan 15 sn. 15 sn'den uzun süren sorgular artık iptal edilir (GC batch'leri 500 satırdır; ölçülmedi).
- (−) `register_max_requests`, `forgot_password_max_requests`, `mfa_max_requests` hâlâ uygulanmıyor: yeni kısıtlama getireceği için karar bekliyor (`DECISIONS_NEEDED.md`).

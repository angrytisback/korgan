# ADR 0003 — Probe rotaları rate limiter dışında

Durum: Kabul edildi · Kusur: A-05

## Bağlam
Rate limit katmanı tüm rotalara uygulanıyordu. Redis erişilemezken limiter fail-closed olduğu için `/health/live` da 503 dönüyordu; bu, liveness probe'unun bağımlılığa bağlı olmaması gerektiği kuralını (handler'ın kendi dokümanı) bozuyor ve orkestratörün sağlıklı pod'ları yeniden başlatmasına yol açabiliyordu. Probe istekleri ayrıca probe eden hostun IP bütçesini tüketiyordu.

## Karar
`/health`, `/health/live`, `/health/ready` ve `/metrics` limiter'dan muaftır (`EXEMPT_PATHS`). Diğer tüm rotalar fail-closed kalır. `/health/ready` zaten Redis ve Postgres'i kendisi sınar.

## Sonuçlar
- (+) Redis kesintisinde pod'lar canlı kalır, readiness 503 ile trafikten çıkarılır.
- (−) Bu rotalar için istemci başına sınır yok; hepsi ucuz ve yan etkisizdir. `/metrics` erişimi hâlâ ağ katmanında (nginx) kısıtlanmalıdır; ayrı dinleyici önerisi için bkz. `DECISIONS_NEEDED.md` (A-12).

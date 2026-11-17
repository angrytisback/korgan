# ADR 0008 — Uç başına rate limit

Durum: Kabul edildi · Kusur: A-15

## Bağlam
`rate_limit.register_max_requests`, `forgot_password_max_requests` ve `mfa_max_requests` doğrulanıyor ama uygulanmıyordu; operatörler bir sınır koyduklarını sanırken yalnızca global bütçe (600/dk) ve login bütçesi geçerliydi.

## Karar
`POST /auth/register`, `POST /password/forgot` ve `POST /auth/mfa/verify` rotaları kendi kovalarına (`ep_rl:<kova>:<ip>`) sahip olur; global limitle birlikte uygulanır. Üç limiter da tek bir çekirdeği (`enforce`) paylaşır. Aşımda `429 + Retry-After`, limiter arka ucu hata verirse `503` (fail-closed). Varsayılanlar (5 / 5 / 10 her pencerede) artık gerçektir. Login bütçesi `rate_limit.login_max_requests`/`window_secs` değerlerinden gelir.

## Sonuçlar
- (+) Kayıt, parola sıfırlama ve MFA deneme denemelerine karşı gerçek, ayarlanabilir koruma. Gerçek Redis ile doğrulandı: 6. kayıt isteği `429`.
- (−) HTTP davranış değişikliği (onaylandı): bütçeyi aşan istemciler artık 429 alır. Reverse proxy arkasında `trust_proxy_headers` doğru ayarlanmazsa tüm istemciler tek IP gibi görünür ve kovayı paylaşır.

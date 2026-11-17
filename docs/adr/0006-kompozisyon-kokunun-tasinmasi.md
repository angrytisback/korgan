# ADR 0006 — Kompozisyon kökünün `bootstrap` modülüne taşınması

Durum: **Kabul edildi; 1. ve 2. adım uygulandı** · Kusur: A-10

## Bağlam
`adapters/inbound/http/state.rs` (717 satır) tüm outbound adaptörleri kuruyor, 20 argümanlı `with_ports` ile ~35 use case'i bağlıyor ve alanlarını `pub` açıyordu. Kompozisyon kökü bir inbound adaptörün içinde olduğu için CLI ve test kurulumları HTTP katmanına bağımlıydı.

## Karar (kademeli)
1. **Yapıldı:** Adaptör kurulumu (`build_pg_pool`, `build_redis_pool`, repository'ler, kripto, mail, OAuth, worker) `src/bootstrap.rs` içine taşındı; `AppState::from_settings` yerine `bootstrap::build_state` geldi. Inbound HTTP adaptörü artık hiçbir outbound adaptörü import etmiyor (referans sayısı ~25 → 0) ve `state.rs` 717 → 434 satıra indi. `AppState`, `with_ports` ve handler imzaları değişmedi.
2. **Yapıldı:** `AppState` yalnızca HTTP katmanının ihtiyaç duyduğu alanları taşır. Yalnızca use case'leri kurmak için var olan ve handler/extractor/middleware tarafından hiç okunmayan dokuz alan (`oauth_account_repo`, `secret_cipher`, `totp_service`, `hibp_client`, `mail_provider`, `google_oauth`, `github_oauth`, `webauthn_service`, `event_bus`) kaldırıldı; kalan alanlar, ikili (GC worker, CLI) ve entegrasyon testlerinin eriştikleri birkaçı dışında `pub(crate)`. `with_ports` imzası aynı kaldı (test kurulumu değişmedi).
3. **Bilinçli olarak yapılmadı:** `with_ports`'taki use case bağlamanın `bootstrap`'e taşınması; handler'ların `state.xxx_use_case` erişimlerini değiştirir ve bu aşamada ek bir sınır kazancı sağlamaz.

## Sonuçlar
- (+) Katman sınırı net: bileşim kökü tek yerde (`bootstrap`), HTTP katmanı yalnızca portlara bağlı.
- (+) Boot ile ilgili işler (migrasyon, havuz) için doğal bir yer oluştu (`bootstrap::run_migrations`).
- (−) `AppState` hâlâ ~35 use case taşıyan geniş bir struct; ancak artık yalnızca HTTP'nin gerçekten kullandığı alanları içerir ve dışarıya kapalıdır.

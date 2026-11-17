# ADR 0006 — Kompozisyon kökünün `bootstrap` modülüne taşınması

Durum: **Kabul edildi; 1. adım uygulandı** · Kusur: A-10

## Bağlam
`adapters/inbound/http/state.rs` (717 satır) tüm outbound adaptörleri kuruyor, 20 argümanlı `with_ports` ile ~35 use case'i bağlıyor ve alanlarını `pub` açıyordu. Kompozisyon kökü bir inbound adaptörün içinde olduğu için CLI ve test kurulumları HTTP katmanına bağımlıydı.

## Karar (kademeli)
1. **Yapıldı:** Adaptör kurulumu (`build_pg_pool`, `build_redis_pool`, repository'ler, kripto, mail, OAuth, worker) `src/bootstrap.rs` içine taşındı; `AppState::from_settings` yerine `bootstrap::build_state` geldi. Inbound HTTP adaptörü artık hiçbir outbound adaptörü import etmiyor (referans sayısı ~25 → 0) ve `state.rs` 717 → 434 satıra indi. `AppState`, `with_ports` ve handler imzaları değişmedi.
2. **Bilinçli olarak yapılmadı:** `AppState`'in alanlarının daraltılması ve `with_ports`'taki use case bağlamanın `bootstrap`'e alınması. Handler'ların ~35 `state.xxx_use_case` erişimini değiştirir; ayrı bir karar/PR olarak ele alınmalıdır.

## Sonuçlar
- (+) Katman sınırı net: bileşim kökü tek yerde (`bootstrap`), HTTP katmanı yalnızca portlara bağlı.
- (+) Boot ile ilgili işler (migrasyon, havuz) için doğal bir yer oluştu (`bootstrap::run_migrations`).
- (−) `AppState` hâlâ geniş bir struct; 2. adım yapılana kadar "tanrı struct" olarak kalır.

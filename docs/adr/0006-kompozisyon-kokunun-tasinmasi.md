# ADR 0006 — Kompozisyon kökünün `bootstrap` modülüne taşınması

Durum: **Önerildi — karar bekliyor** · Kusur: A-10

## Bağlam
`adapters/inbound/http/state.rs` (~700 satır) tüm outbound adaptörleri kurar, 20 argümanlı `with_ports` ile ~35 use case'i bağlar ve tüm alanlarını `pub` açar. Kompozisyon kökü bir inbound adaptörün içinde olduğu için CLI ve test kurulumları HTTP katmanına bağımlıdır; "tanrı struct" değişikliği zorlaştırır.

## Önerilen karar
`src/bootstrap/` oluştur: pool/adaptör kurulumu (`build_pg_pool` ve `build_redis_pool` zaten ayrı fonksiyonlar), use case bağlama ve worker başlatma burada olsun; `AppState` yalnızca handler'ların ihtiyaç duyduğu use case'leri taşısın. Kademeli yapılabilir: önce fonksiyonları taşı, sonra alanları daralt.

## Sonuçlar
- (+) Katman sınırları netleşir, test kurulumu sadeleşir.
- (−) Geniş bir yapısal taşıma; "komple mimari değişiklik" kapsamına girebileceği için konuşulmadan yapılmadı.

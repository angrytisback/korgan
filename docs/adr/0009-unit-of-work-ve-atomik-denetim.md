# ADR 0009 — Unit of work ve atomik denetim

Durum: Kabul edildi · Kusur: A-02 (tam atomiklik) · Tamamlar: [ADR 0005](0005-denetim-icin-transactional-outbox.md)

## Bağlam
ADR 0005'teki outbox, olayı istek dönmeden önce kalıcı yazıyordu ama iş değişikliğiyle **aynı SQL transaction'ında** değildi: commit ile enqueue arasında süreç ölürse tek bir olay kaybolabilir, ya da tersine bir denetim kaydı hiç gerçekleşmemiş bir değişikliği anlatabilirdi. Denetim çağrıları, PG mutasyonlarını ve Redis işlemlerini karıştıran use case'lerin içinde dağınıktı (32 çağrı noktası).

## Karar
- `application::unit_of_work::UnitOfWork` portu: `run(work)` bir transaction açar; `work` `Ok` dönerse commit, `Err` dönerse veya future düşürülürse (istemci kopması) rollback.
- Postgres adaptörü (`PostgresUnitOfWork`) transaction'ı bir **task-local** olarak yayımlar. Repository'ler bağlantıyı `DbConn::acquire` ile alır: görev bir unit of work içindeyse ortam transaction'ı, değilse havuzdan bağlantı. Repository'lerin kendi `begin()` çağrıları unit of work içinde savepoint olur. İç içe `run` dıştaki transaction'a katılır.
- `EventBus::audited(work, audit)` ve `audited_with(work, |sonuç| audit)`: iş ve `audit_outbox` INSERT'i tek transaction'da çalışır; audit yazılamazsa iş geri alınır (fail-closed). Unit of work/outbox yoksa (bellek içi fake'ler) `work` + `record_audit`'e düşer; böylece use case constructor'ları değişmedi.
- Bir audit olayı **PG mutasyonu anlatıyorsa** `audited` kullanılır (kayıt, giriş + sayaç sıfırlama, başarısız giriş sayacı/kilit, MFA, şifre, oturum, ban/unban, passkey, OAuth, token tekrar kullanımı...). **PG mutasyonu yoksa** (hız sınırı, bilinmeyen kullanıcı, engellenmiş giriş, Redis-only akışlar, passkey okuma hataları, forgot-password) `record_audit` kalır; birlikte atomik olacak bir şey yoktur (11 çağrı noktası).
- Redis yan etkileri (kara liste senkronu, rate limiter sıfırlama) transaction dışında, commit'ten sonra çalışır. PG ve Redis arasında dağıtık atomiklik yoktur ve hedeflenmemiştir.

## Kısıtlar
- `work` doğrudan repository çağrıları yapmalıdır; **`tokio::spawn`/`shielded` içermemelidir**: başka bir task ortam transaction'ına katılmaz ve kilitlenme riski doğurur.
- `work` içinde uzun süreli dış I/O (Argon2, HIBP, Redis, HTTP) bulunmamalıdır; transaction bağlantı tutar. Dönüştürülen bloklar yalnızca kısa DB çağrıları içerir.

## Sonuçlar
- (+) Kabul edilmiş bir değişiklik ile denetim kaydı ya birlikte vardır ya hiç yoktur; boşluk penceresi kapandı.
- (+) Gerçek PostgreSQL 17 ile doğrulandı: commit, iş hatasında rollback, audit INSERT hatasında rollback (fail-closed), çağıran iptalinde rollback, **tek bağlantılı havuzda 20 eşzamanlı unit of work** (ikinci bağlantı alınmadığının kanıtı). Atomik yolu devre dışı bırakan bir mutasyon bu testlerin üçünü kırar.
- (+) Maliyet: tek sıralı çağıran için ≈ 1.4 ms (aynı transaction'da ek bir INSERT), 16 eşzamanlıda ölçüm gürültüsü içinde; bkz. `docs/LOAD_TESTING.md`.
- (−) İstek yolu bir DB transaction'ı bekler; DB kapalıyken denetim kaydı için bellek içi yedek yol yoktur çünkü aynı transaction başarısız olur (değişiklik de olmaz).
- (−) Ortam transaction'ı örtük bir mekanizmadır; yeni bir `tokio::spawn` eklenirse sessizce dışarıda kalır. Bu yüzden kısıtlar kodda ve burada belgelidir.

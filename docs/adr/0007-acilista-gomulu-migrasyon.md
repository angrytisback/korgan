# ADR 0007 — Açılışta gömülü migrasyon

Durum: Kabul edildi · Kusur: A-04

## Bağlam
`database.run_migrations` (varsayılan `true`) kabul ediliyor ama hiçbir şey yapmıyordu; README manuel `cargo sqlx migrate run` diyor, mimari belgeleri ise "açılışta otomatik" diyordu.

## Karar
Migrasyonlar `sqlx::migrate!("./migrations")` ile ikiliye gömülür (`bootstrap::MIGRATOR`) ve `run_migrations = true` iken, CLI komutları ve sunucu veritabanına dokunmadan önce `bootstrap::run_migrations` ile uygulanır. sqlx, çalışırken PostgreSQL advisory lock tutar; aynı anda açılan birden çok replika güvenle sıraya girer. Ayrı bir release adımıyla migrasyon yapan ortamlar `run_migrations = false` yapar.

## Sonuçlar
- (+) Boş bir veritabanıyla tek ikili çalışır; dokümanlardaki "gömülü migrasyon" iddiası doğru olur.
- (+) Gerçek PostgreSQL 17 ile doğrulandı: boş DB, idempotans, 4 eşzamanlı çalıştırıcı, ve gerçek süreç açılışında 9 migrasyon.
- (−) Uygulama kullanıcısının DDL yetkisi olmalıdır; değilse `run_migrations = false` ve ayrı yetkili adım kullanılmalıdır.
- (−) Uygulanmış bir migrasyon dosyası değiştirilirse sqlx checksum hatası verir ve açılış başarısız olur (istenen davranış).

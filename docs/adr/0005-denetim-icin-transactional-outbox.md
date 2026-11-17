# ADR 0005 — Denetim teslim garantisi için transactional outbox

Durum: **Kabul edildi ve uygulandı** · Kusur: A-02

## Bağlam
Denetim defteri hash zincirli, değişmez ve "eksiksiz" olarak tanıtılıyor. Ancak olaylar bellek içi bounded kuyruğa `try_send` ile bırakılıyordu: kuyruk dolarsa veya süreç çökerse olay kayboluyordu. [ADR 0001](0001-olay-teslimi-ve-mail-izolasyonu.md) kaybı görünür yaptı fakat engellemedi.

## Karar
- Yeni tablo `audit_outbox` (migrasyon `0009`): `seq` (kimlik), `payload` (serileştirilmiş `AuditLog`), `enqueued_at`, `quarantined_at`.
- `ports::AuditOutbox` (`enqueue`, `drain`, `pending`); Postgres'te `PostgresAuditLogRepository` uygular.
- **Üretici:** `EventBus::record_audit` (32 çağrı noktasında `dispatch(LogAudit)` yerine) olayı tek bir kilitsiz `INSERT` ile kalıcı kuyruğa yazar. İş `shielded` ile iptale karşı korunur ve geçici hatalarda yeniden denenir. Outbox'ın kendisi başarısız olursa bellek içi kuyruğa (eski yol) düşer; böylece DB sorunu isteği bozmaz.
- **Tüketici:** `EventWorker`, `wake` bildirimiyle ve `audit_outbox_poll_ms` aralığıyla outbox'ı boşaltır. `drain`, tek transaction'da: mevcut advisory lock'u alır, en eski `audit_outbox_batch_size` satırı okur, zincire ekler (aynı monoton zaman damgası kuralı) ve satırları siler. Böylece her olay tam bir kez zincirlenir ve olay başına değil batch başına bir kez kilit alınır.
- Çözümlenemeyen (ör. sürüm farkı) satırlar `quarantined_at` ile karantinaya alınır; silinmez ve kuyruğu tıkamaz.
- Ayarlar: `workers.audit_outbox_batch_size` (200), `workers.audit_outbox_poll_ms` (1000). Metrikler: `korgan_audit_outbox_pending`, `korgan_audit_outbox_enqueue_failures_total`, `korgan_audit_outbox_quarantined_total`.

## Alternatifler
- Audit için `send().await` (backpressure): istek gecikmesi zincir hızına bağlanır, çökmeye karşı koruma yok.
- Olayı iş işlemiyle **aynı SQL transaction'ında** yazmak: başlangıçta ertelendi; ardından kullanıcı kararıyla uygulandı, bkz. [ADR 0009](0009-unit-of-work-ve-atomik-denetim.md).

## Sonuçlar
- (+) Kabul edilmiş bir denetim olayı dolu kuyruk, yeniden başlatma veya çökme yüzünden kaybolmaz (gerçek PostgreSQL 17 ile doğrulandı: eşzamanlı üretici/tüketici, tam-bir-kez zincirleme, yeniden başlatma, karantina, kapasite-1 kuyrukla uçtan uca).
- (+) Zincir yazımı batch'lendiği için kilit baskısı azalır; HA'da her replika kuyruğu boşaltabilir.
- (+) **Atomiklik:** PG mutasyonu anlatan olaylar [ADR 0009](0009-unit-of-work-ve-atomik-denetim.md) ile iş değişikliğiyle aynı SQL transaction'ında yazılır; commit ile enqueue arasındaki boşluk kapandı. PG mutasyonu olmayan olaylar (hız sınırı, Redis-only akışlar) bağımsız `record_audit` ile kalıcı yazılır.
- (−) Outbox DB'ye bağlıdır: DB yokken yedek yol bellek içi kuyruktur (eski best-effort davranış).
- (−) Yeni tablo: `run_migrations = false` ise sürümle birlikte migrasyon elle uygulanmalıdır; uygulanmazsa enqueue başarısız olur ve yedek yol devreye girer (hata loglanır).

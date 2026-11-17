# ADR 0001 — Olay teslimi: e-posta, denetim yolundan ayrılır

Durum: Kabul edildi · Kusurlar: A-02 (kısmen), A-03

## Bağlam
Tüm yan etkiler (denetim kaydı, doğrulama/sıfırlama e-postası) tek bir bounded `mpsc` kuyruğundan geçer ve tek bir `EventWorker` tarafından sırayla işlenirdi. SMTP/Resend gönderimi yavaşladığında (lettre varsayılan zaman aşımı ~60 sn) aynı döngüdeki denetim yazımı da beklerdi. Kuyruk dolunca `dispatch` (`try_send`) olayı sessizce düşürürdü; bu da denetim zincirinde kayıp demekti.

## Karar
- Denetim olayları aynı task'ta, sırayla yazılmaya devam eder (zincir zaten `pg_advisory_xact_lock` ile tek yazıcıya serileştirilmiştir).
- E-postalar `JoinSet` ile ayrı task'larda, en fazla 8 eşzamanlı, en fazla 256 bekleyen ve gönderim başına 15 sn zaman aşımıyla gönderilir. Taşma durumunda e-posta düşer ve sayılır.
- Düşen her olay `korgan_events_dropped_total{kind,reason}` sayacını artırır ve loglanır. Kuyruk kapasitesi `workers.event_queue_capacity` ile ayarlanır (varsayılan 1024).
- `EventBus` API'si değişmedi; `AppEvent::kind()` eklendi.

## Alternatifler
- Ayrı kanallar (audit/mail): `EventBus::new` imzasını ve ~35 çağrı noktasını etkiler; kazanç ayrı task'larla aynı.
- Mail için sınırsız `spawn`: bellek sınırsız büyür.

## Sonuçlar
- (+) Yavaş mail sunucusu denetim yazımını geciktirmez (test: `stalled_mail_provider_does_not_block_audit_persistence`).
- (+) Kayıp artık görünür ve alarmlanabilir.
- (−) Denetim kuyruğu dolarsa olay hâlâ düşer. Tam garanti için bkz. [ADR 0005](0005-denetim-icin-transactional-outbox.md).
- (−) E-posta sırası artık garanti edilmez (zaten gerekli değildi).

# ADR 0004 — Worker yaşam döngüsü ve kapanış sırası

Durum: Kabul edildi · Kusurlar: A-01, A-08, A-11, A-16

## Bağlam
- Kapalı bir `watch` kanalında `changed()` anında `Err` döner. `build_app` stop sender'ı düşürdüğü için `EventWorker` hiç `Pending` dönmeyen bir döngüye giriyor ve çalıştığı executor thread'ini donduruyordu (testle kanıtlandı).
- `main`, sunucu hata verirse worker'ları sinyallemeden çıkıyor, `JoinError`'ları yutuyordu.
- DB'ye bağlı gauge senkronu soket açılmadan çalışıp DB kapalıyken açılışı ~10 sn geciktiriyordu.
- `SessionPurgeWorker` kullanılmıyordu.

## Karar
- `EventWorker`: stop kanalı kapanırsa o dal devre dışı kalır ve worker olay kuyruğu kapanana kadar çalışır. Periyodik worker'larda kapanmış kanal durdurma sinyalidir.
- Kapanış sırası: sunucu sonucu saklanır → shielded task'lar `workers.shutdown_drain_secs` kadar beklenir → worker'lar sinyallenir ve `join_worker` ile beklenir (anormal çıkış loglanır ve çıkış kodunu bozar) → sunucu hatası varsa döndürülür.
- Gauge senkronu bind sonrası arka planda çalışır (DB kapalıyken dinleme süresi ~0.3 sn).
- `SessionPurgeWorker` silindi (`RetentionGcWorker` aynı işi yapar).

## Sonuçlar
- (+) Temiz olmayan çıkışta bile bekleyen olaylar drain edilir.
- (−) Henüz `JoinSet`/`TaskTracker`/`CancellationToken` yok; ham `tokio::spawn` + `watch` kaldı. Tam yapılandırılmış eşzamanlılık ayrı bir iş olarak açık.
- (−) `cancellation.rs` içindeki işlem-global sayaç (A-09) değişmedi.

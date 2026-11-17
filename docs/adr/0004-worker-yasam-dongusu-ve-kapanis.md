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
- Periyodik GC adımı (`run_periodic`) kapanışta iptal edilir: DB erişilemezken her purge adımı acquire zaman aşımını bekliyordu ve SIGTERM ~10 sn sürüyordu; şimdi <1 ms (ölçüldü). Purge'lar idempotent batch'lerdir, yarıda kesmek güvenlidir.
- `shielded` yalnızca geçici hatalarda (`Internal`, `ServiceUnavailable`) en fazla 3 kez dener; deterministik hatalar (conflict, forbidden, not found, geçersiz token) hemen döner (A-09). Süreç-global drain sayacı bilinçli olarak korunur: bir süreçte tek kapanış drain'i vardır; gerekçesi kodda belgelidir.
- `/metrics` için isteğe bağlı ayrı dinleyici (`server.metrics_addr`) iki dinleyiciyi tek kapanış sinyaline bağlar.

## Sonuçlar
- (+) Temiz olmayan çıkışta bile bekleyen olaylar drain edilir.
- (−) Henüz `JoinSet`/`TaskTracker`/`CancellationToken` yok; ham `tokio::spawn` + `watch` kaldı. Tam yapılandırılmış eşzamanlılık ayrı bir iş olarak açık.
- (−) İşlem-global shielded sayacı testlerde paylaşılan durumdur; `TaskTracker` (tokio-util) bağımlılık eklemeyi gerektirdiği için yapılmadı.

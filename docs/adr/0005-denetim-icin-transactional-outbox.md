# ADR 0005 — Denetim teslim garantisi için transactional outbox

Durum: **Önerildi — karar bekliyor** · Kusur: A-02

## Bağlam
Denetim defteri hash zincirli, değişmez ve "eksiksiz" olarak tanıtılıyor. Ancak olaylar bellek içi bounded kuyruğa `try_send` ile bırakılıyor: kuyruk dolarsa veya süreç kapanış sırasında çökerse olay kaybolur. [ADR 0001](0001-olay-teslimi-ve-mail-izolasyonu.md) kaybı görünür yaptı fakat engellemedi.

## Önerilen karar
İş işlemi ile aynı Postgres işleminde bir `audit_outbox` satırı yazılır; worker satırları `FOR UPDATE SKIP LOCKED` ile alıp zincire ekler ve siler.

## Alternatifler
- Audit için `send().await` (backpressure): istek gecikmesi DB/zincir hızına bağlanır, çökmeye karşı koruma yok.
- Mevcut durum + sayaç: kayıp mümkün kalır.

## Sonuçlar
- (+) Çökme ve taşmaya karşı gerçek garanti.
- (−) Yeni tablo ve migrasyon (şema değişikliği), ~35 use case çağrısının işleme dahil edilmesi, ek gecikme. Bu yüzden kullanıcı kararı gerekir.

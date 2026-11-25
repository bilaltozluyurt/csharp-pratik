# C# Pratik

Mülakat hazırlığı için C# ve .NET konu anlatımları, "şunu kodla" görevleri ve kendi çözümlerim.

## Yapı

| Klasör | İçerik |
|---|---|
| `public/` | Pratik sayfası ve giriş sayfası. Cloudflare Workers sadece bu klasörü yayınlar. |
| `src/worker.js` | Oturum ve sayfa koruması (D1). Giriş yapmadan sadece `giris.html` açılır. |
| `solutions/` | Kendi çözümlerim. Her görev, kategori klasöründe `G<no>_<Ad>.cs` adlı static bir class. Tek konsol projesi olarak derlenir. |
| `labs/` | ASP.NET Core ve test görevleri için ayrı projeler. |

## Çalıştırma

```bash
git pull
dotnet run --project solutions          # commit edilmiş görevleri listeler
dotnet run --project solutions -- 41    # 41 numaralı görevi çalıştırır
```

## Çalışma döngüsü

1. Sayfada konu anlatımını oku.
2. Editörde `Run()` metodunun içine kendi çözümünü yaz ve commit et.
3. Sayfadaki çözümle karşılaştır.
4. Ertesi gün çözüme bakmadan aynı görevi tekrar yaz.

## Giriş sistemi (D1)

Site tek kullanıcılı bir giriş sayfasıyla korunur: e-posta + şifre, 30 günlük oturum çerezi, hatalı denemede 15 dakikalık kilit. Şifre PBKDF2 ile hash'lenir, oturum token'ının sadece özeti saklanır.

Kurulum:
1. `npx wrangler d1 create csharp-pratik` → çıkan `database_id`'yi `wrangler.jsonc` içine yaz.
2. `npx wrangler secret put KURULUM_KODU` → uzun, tahmin edilemez bir metin.
3. `npx wrangler deploy`
4. Siteyi aç: ilk kurulum ekranında kurulum kodu + e-posta + şifre ile hesabını oluştur. Bundan sonra kurulum kapanır.

Sayfadaki **Hesap** düğmesinden çıkış yapılır ve şifre değiştirilir.

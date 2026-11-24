# C# Pratik

Mülakat hazırlığı için C# ve .NET konu anlatımları, "şunu kodla" görevleri ve kendi çözümlerim.

## Yapı

| Klasör | İçerik |
|---|---|
| `public/` | Pratik sayfası. Cloudflare Workers sadece bu klasörü yayınlar. |
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

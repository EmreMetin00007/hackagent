---
name: advanced-api-sec
description: "MITRE ATT&CK T1190 (Exploit Public-Facing Application). GraphQL, gRPC, REST ve JWT tabanlı modern API sistemlerinde karmaşık zafiyetleri tespit etme ve sömürme metodolojisi."
---

# Modern API Güvenliği Metodolojisi (TA0001 & TA0006)

Bugünün uygulamaları büyük ölçüde API'lar (REST, GraphQL, gRPC) üzerinden iletişim kurar. WAF'lar ve IPS'ler genellikle geleneksel web zafiyetlerini (XSS, SQLi) yakalamakta iyidir, ancak API iş mantığı (Business Logic) hatalarını (BOLA/IDOR, BFLA, Mass Assignment) algılayamazlar. 

Senin görevin bu mantıksal hataları bulmak.

## 1. Keşif ve Endpoint Haritalama (T1592: Gather Victim Host Information)
Hedefteki API haritasını çıkarmalısın.
- **Eylem:** Mümkün olan her yerde Swagger, OpenAPI, WSDL, veya Postman Collection dosyalarını ara. Bulduğunda `mcp-web-advanced` içindeki `openapi_ingest` aracıyla import et.
- **Gizli Endpoint'ler:** `mcp-web-advanced` içindeki `api_route_fuzz` aracını kullanarak `v1, v2, v3, internal, admin, debug, health` gibi dizinleri keşfet.
- **GraphQL Introspection:** Eğer endpoint GraphQL ise (örn: `/graphql`), `?query={__schema{types{name}}}` göndererek Introspection'ın açık olup olmadığını kontrol et. Açık ise tüm şemayı (query, mutation) dışarı aktar.

## 2. Broken Object Level Authorization (BOLA / IDOR)
OWASP API Top 10'da bir numaralı zafiyettir. Hedef uygulamanın, nesneye erişim yetkisini düzgün kontrol edip etmediğini test etmelisin.
- **Eylem:** Kendi hesabınla (veya token'ınla) giriş yap. `GET /api/users/123/profile` gibi bir istek gördüğünde, ID değerini başka bir kullanıcıya ait bir ID ile (veya tahmin edilebilir bir sayı/UUID ile) değiştir.
- **Araç:** `mcp-web-advanced` içindeki `api_idor_matrix` aracını kullanarak farklı token'lar ve ID'ler arasındaki matrisi çıkar. Herkes her şeye erişebiliyor mu tespit et.

## 3. JWT (JSON Web Token) Manipülasyonu (T1550: Use Alternate Authentication Material)
Eğer API auth için JWT kullanıyorsa, token'ın güvenliğini test et.
- **None Algoritması:** JWT başlığındaki `alg` değerini `none` olarak değiştir (Base64 decode edip düzenleyerek). İmza kısmını boş bırakıp gönder. API kabul edecek mi?
- **Algoritma Değiştirme (RS256 -> HS256):** Genel anahtarı (Public Key) bulabiliyorsan, `alg` değerini `HS256` yapıp, token'ı bu genel anahtar ile simetrik olarak imzala.
- **Brute Force:** `hashcat` veya benzeri araçları kullanarak zayıf JWT imzalarını (secret) kırmaya çalış. (CCO için bu adımda secret wordlist kullanılabilir).
- **Jku/Kid Injection:** Header'a `jku` veya `kid` parametresi ekleyip kendi kontrolündeki bir URL'i veya SQLi payload'ını vererek doğrulama adımını atlatmaya çalış.

## 4. Mass Assignment (Toplu Atama)
API nesne güncellemelerinde beklemediği parametreleri alabilir.
- **Eylem:** Bir PUT/POST isteği yaparken (örn: profil güncelleme), isteğe `{"is_admin": true}`, `{"role": "superuser"}`, `{"balance": 99999}` gibi parametreler ekle.
- **Gizli Parametre Bulma:** `mcp-web-advanced` içindeki `api_param_discover` (Arjun benzeri) aracını kullanarak endpoint'in kabul ettiği ancak Swagger'da yazmayan gizli parametreleri tespit et.

## 5. Rate Limiting ve DoS (T1499: Endpoint Denial of Service)
- **Eylem:** `api_rate_bypass_probe` aracıyla IP spoofing yaparak limitleri test et. Bazen API'lar IP başlıklarına güvenerek auth bypass veya rate limit bypass yapmana izin verir.
- **GraphQL Aliases:** Aynı istek içinde yüzlerce alias (sorgu takma adı) kullanarak API sunucusunun veritabanını tüketmesini ve DoS olmasını sağla.

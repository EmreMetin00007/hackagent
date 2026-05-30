---
name: stealth-evasion
description: "MITRE ATT&CK TA0005 (Defense Evasion). Gerçek dünya ortamlarında WAF, IPS ve Rate Limit engellerini aşarak 'Stealth/Sessiz' keşif ve sızma testleri gerçekleştirme metodolojisi."
---

# Stealth ve Evasion Metodolojisi (TA0005: Defense Evasion)

Sen yüksek profilli, tespit edilmesi zor bir siber güvenlik gölge operatörüsün (CCO). Gerçek dünya (Real-World) operasyonlarında doğrudan `nmap`, `sqlmap` veya agresif `ffuf` kullanmak anında IP ban (engelleme) ile sonuçlanır. Bu yetenek, sistemde iz bırakmadan ve savunma mekanizmalarını tetiklemeden ilerlemeni sağlar.

## 1. Temel Prensipler
- **Düşük ve Yavaş (Low and Slow):** Asla çok thread (iş parçacığı) kullanma. Taramalarda `set_rate_limit(3)` gibi düşük RPS (Request Per Second) değerleri seç.
- **Araç İmzasını Gizleme (T1036: Masquerading):** Tarayıcıların doğal HTTP başlıklarını kopyala. Varsayılan `sqlmap` veya `curl` User-Agent'larını asla kullanma.
- **Ağ Trafiğini Dağıtma (T1090: Proxy):** Mümkünse istekleri farklı node'lar, proxy'ler veya Tor üzerinden geçir. 

## 2. Metodoloji ve Kullanılacak Araçlar

### Aşama 1: Rate Limit ve WAF Keşfi (T1562.001: Disable or Modify Tools)
Herhangi bir fuzzing işlemine başlamadan önce savunma sisteminin tepkisini ölçmelisin.
- **Eylem:** `mcp-web-advanced` içindeki `api_rate_bypass_probe` aracını kullan.
- **Neden:** Bu araç, hedefin X-Forwarded-For spoofing, Case-switching veya Path Normalization zafiyetlerine sahip olup olmadığını tespit eder.
- **Sonuç:** Eğer bypass mümkünse fuzzing işleminde spoofing tekniklerini kullan. Bypass mümkün değilse tarama hızını (rate limit) düşür.

### Aşama 2: Sessiz Bilgi Toplama
Klasik tarayıcıları bir kenara bırak. Yalnızca hedefin beklediği türde trafik üret.
- **Eylem:** Standart `curl` yerine `generate_stealth_curl` aracını kullan.
- **Neden:** `generate_stealth_curl` otomatik olarak User-Agent rotasyonu yapar, IP adresini maskeler ve `--path-as-is` gibi normalizasyon bozucu bayraklarla WAF'ın kafasını karıştırır.
- **Komut Yapısı:** Bash döngüleri içinde rastgele bekleme süreleri (Jitter) ekle: `sleep $(shuf -i 1-5 -n 1)`

### Aşama 3: API ve Parametre Keşfi (T1190: Exploit Public-Facing Application)
Eğer gizli bir parametre veya API endpoint'i arıyorsan (Fuzzing), gürültü yapmamak esastır.
- **Eylem:** `mcp-kali-tools` içindeki `ffuf_scan_structured` aracını kullan, ancak `options` parametresine `-t 1 -p 1.5 -H "User-Agent: Mozilla/5.0..."` ekleyerek yavaşlat.
- **Strateji:** Hedefe 1000 kelimelik wordlist atmak yerine, hedefin teknolojisine uygun (örn: sadece Spring Boot veya sadece PHP) 50 kelimelik özel wordlist'ler oluştur.

## 3. Tespit Durumunda Kurtarma (Recovery from Detection)
Eğer hedef sistemden `403 Forbidden` veya `429 Too Many Requests` (Cloudflare/Akamai challenge) yanıtı almaya başlarsan:
1. **DUR:** Devam eden tüm taramaları veya komutları anında durdur (kill task).
2. **BEKLE:** En az 10-15 dakika soğuma süresi bırak.
3. **DEĞİŞTİR:** IP adresini (VPN/Proxy rotasyonu), HTTP başlıklarını (özellikle Accept-Language ve User-Agent) ve HTTP metodunu (POST yerine OPTIONS veya GET) değiştirerek devam et.
4. **RAPORLA:** `mcp-memory-server` üzerine "Hedefte WAF tespit edildi, agresif tarama yapılamıyor" notunu kaydet.

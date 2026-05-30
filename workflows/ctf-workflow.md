# 🏴 CTF Challenge Çözüm İş Akışı

Bu doküman HackerAgent orkestratörünün bir CTF challenge'ını çözerken takip edeceği iş akışını tanımlar.

## Ana Akış

```
Challenge Alındı
│
├── 1. GÖZLEM (OBSERVE)
│   ├── Challenge açıklamasını oku
│   ├── Dosya(lar)ı indir
│   ├── Hedef URL/IP/servis bağlanabilirliğini kontrol et
│   ├── Puan ve ipuçlarını not et
│   └── Challenge adında kelime oyunu var mı?
│
├── 2. KATEGORİLENDİRME
│   ├── Otomatik kategori tespiti (karar ağacına bak)
│   ├── Alt kategori belirle
│   └── Zorluk tahmin et
│
├── 3. STRATEJİ (ORIENT + DECIDE)
│   ├── Muhtemel çözüm yollarını listele
│   ├── En olası yolu seç
│   ├── Gerekli araçları belirle
│   └── Adım adım plan yap
│
├── 4. UYGULAMA (ACT)
│   ├── Planı uygula
│   ├── Her adımın çıktısını analiz et
│   ├── Flag pattern kontrolü yap
│   │
│   ├── Başarılı mı? → Flag'i doğrula → Writeup yaz → BİTİR
│   │
│   └── Başarısız mı? → 
│       ├── Neden başarısız olduğunu analiz et
│       ├── Farklı strateji seç → 3'e dön
│       ├── Farklı kategori olabilir mi? → 2'ye dön
│       └── Daha fazla bilgi gerekli mi? → 1'e dön
│
└── 5. RAPORLAMA
    ├── Writeup oluştur
    ├── Kullanılan araçları listele
    └── Öğrenilen dersleri not et
```

## Kategori Bazlı Akışlar

### 🌐 WEB Challenge Akışı
```
1. URL'yi aç, kaynak kodu incele
2. robots.txt, sitemap.xml, .git/ kontrol et
3. Cookie ve header'ları incele
4. Dizin taraması yap
5. Input noktalarını bul
6. Her input'u test et (SQLi, XSS, SSTI, CMDi, LFI, SSRF...)
7. Authentication/Authorization test et
8. Kaynak kod varsa white-box analiz
9. Exploit yaz → flag al
```

### 💀 PWN Challenge Akışı
```
1. file + checksec ile analiz
2. strings ile ipuçları
3. Binary'yi çalıştır, input/output davranışını gözlemle
4. Ghidra ile decompile → zafiyet bul
5. GDB ile dinamik analiz → offset hesapla
6. Güvenlik kontrollerine göre exploit stratejisi belirle
7. pwntools ile exploit yaz
8. Lokal test → remote exploit → flag al
```

### 🔄 REVERSE Challenge Akışı
```
1. file ile tip belirle
2. strings ile flag pattern/ipuçları
3. Decompile (Ghidra/jadx/uncompyle6/dnSpy)
4. Main fonksiyonunu bul
5. Flag kontrol/oluşturma mantığını anla
6. Gerekirse:
   - Z3/angr ile otomatik çöz
   - GDB ile dinamik analiz
   - Anti-debug bypass
7. Flag'i reconstruct et
```

### 🔐 CRYPTO Challenge Akışı
```
1. Verilen verileri tanımla (ciphertext, parameters, key fragments)
2. Cipher/encoding tipini belirle
3. Known attack'ları uygula
4. Custom cipher ise analiz et
5. Script yaz → flag al
```

### 🔬 FORENSICS Challenge Akışı
```
1. file + xxd + exiftool ile dosya analizi
2. strings ile ipuçları
3. binwalk ile gömülü dosya kontrolü
4. Dosya tipine göre:
   - Resim → steganografi araçları
   - PCAP → Wireshark/tshark analiz
   - Memory → Volatility
   - Disk → autopsy/sleuthkit
   - Archive → şifre kırma
5. Çıkan veriyi analiz et → flag al
```

### 🌍 OSINT Challenge Akışı
```
1. Verilen ipucunu analiz et
2. Resim → exif GPS, reverse image, geolocation
3. Username → sherlock, social media
4. Domain → WHOIS, DNS history, archive.org
5. Bilgileri birleştir → flag al
```

## Genel Taktikler

- **Basit şeylerden başla**: strings, file, xxd her zaman ilk adım
- **Flag format'ını bil**: `grep -rEi "flag{|CTF{" *`
- **Encoding zincirleri**: base64 → hex → ROT13 gibi çoklu encoding olabilir
- **Dosya adı ipuçları**: Dosya adı veya challenge adı genellikle tekniği işaret eder
- **Hint'leri kullan**: Hint puanı düşürür ama çözüm sağlar
- **Google it**: Benzer challenge writeup'ları altın madeni
- **CyberChef**: Encoding/decoding/crypto için bir numaralı araç

## Flag Doğrulama

```bash
# Her çıktıda flag pattern kontrolü:
echo "ÇIKTI" | grep -oP '[A-Za-z0-9_]+\{[^\}]+\}'
# veya
echo "ÇIKTI" | grep -oEi "(flag|ctf|htb|thm|pico)\{[^}]+\}"
```

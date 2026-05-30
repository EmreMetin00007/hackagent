---
name: ctf-solver
description: "CTF (Capture The Flag) challenge çözücü skill'i. Web, Pwn, Reverse, Crypto, Forensics, OSINT, Misc tüm kategorilerdeki challenge'ları otomatik analiz edip çözme. Bu skill'i şu durumlarda kullan: kullanıcı 'CTF', 'challenge', 'flag bul', 'flag{', 'CTF çöz', 'writeup', 'capture the flag', 'HackTheBox', 'TryHackMe', 'CTFd', 'PicoCTF', 'challenge dosyası', 'flag nerede' dediğinde veya bir CTF challenge'ının çözümü istendiğinde. Herhangi bir CTF challenge analizi, çözümü veya writeup görevi olduğunda mutlaka bu skill'i kullan. Ayrıca bir dosya/binary/web uygulaması verilerek 'bunun içinde ne var', 'bunu çöz', 'hidden data bul' gibi isteklerle de tetiklenir."
---

# 🏴 CTF Challenge Çözücü — Ana Orkestratör

Tüm CTF kategorilerindeki challenge'ları sistematik ve iteratif olarak çözmek için ana orkestrasyon skill'i. Bu skill diğer skill'leri (recon-enumeration, web-exploit, binary-pwn, crypto-forensics) ihtiyaca göre çağırır ve koordine eder.

## Temel İlke

**"Her challenge'ın bir çözümü var — yeterince farklı açıdan bakman gerekir."**

## OODA Döngüsü — Her Challenge İçin

```
🔍 OBSERVE (Gözlem)
├── Challenge açıklamasını oku
├── Dosyaları indir ve analiz et
├── Hedef web/servis/binary'yi tanımla
└── İlk bulguları kaydet

🧭 ORIENT (Yönelim)
├── Kategoriyi belirle (Web? Pwn? Crypto? Forensic? Misc?)
├── Zorluk seviyesini tahmin et
├── Muhtemel zafiyet/çözüm yollarını listele
└── Gerekli araçları belirle

🎯 DECIDE (Karar)
├── En olası çözüm yolunu seç
├── Araç ve tekniği belirle
└── Adım adım plan yap

⚡ ACT (Eylem)
├── Planı uygula
├── Sonuçları gözlemle
├── Başarısızsa → ORIENT'e dön, farklı yol dene
└── Flag bulunduğunda → Doğrula ve raporla
```

## Kategori Tanımlama Karar Ağacı

```
Challenge dosyası/hedefi alındı
│
├── URL/IP verildi mi?
│   ├── Web sayfası → WEB kategorisi
│   ├── Port numarası (ssh, ftp, smb) → NETWORK/MISC kategorisi
│   └── Belirli bir servis → Servis bazlı analiz
│
├── Dosya verildi mi?
│   ├── file komutu çalıştır
│   ├── ELF/PE executable → PWN veya REVERSE kategorisi
│   │   ├── "flag" fonksiyonu var mı → PWN (exploit et)
│   │   └── input almıyor → REVERSE (analiz et)
│   ├── Resim (PNG/JPG/BMP/GIF) → FORENSICS (steganografi)
│   ├── Audio (WAV/MP3) → FORENSICS (audio steg)
│   ├── PDF → FORENSICS (metadata, gömülü dosya)
│   ├── ZIP/RAR/7z → FORENSICS (şifre kır veya forensics)
│   ├── PCAP/PCAPNG → FORENSICS (network analiz)
│   ├── Memory dump → FORENSICS (Volatility)
│   ├── Disk image → FORENSICS (disk forensics)
│   ├── .py/.js/.c/.java → REVERSE veya CRYPTO (kaynak analiz)
│   ├── Metin dosyası → CRYPTO (encoding/cipher)
│   └── Bilinmeyen → binwalk, xxd, strings ile analiz
│
├── Sadece metin/sayı verildi mi?
│   ├── Şifreli görünüyor → CRYPTO
│   ├── Base64/Hex gibi → ENCODING
│   └── Matematiksel problem → CRYPTO/MISC
│
└── OSINT ipucu verildi mi?
    ├── Fotoğraf → Geolocation, metadata
    ├── Kullanıcı adı → Platform araması
    └── Domain/email → OSINT araçları
```

## Kategori Bazlı Çözüm Prosedürleri

### 🌐 WEB
```
1. Sayfa kaynağını incele (view-source)
   └── HTML yorumları, gizli formlar, JavaScript ipuçları
2. robots.txt, sitemap.xml, .well-known/ kontrol et
3. Cookie'leri incele (JWT? Base64? Custom?)
4. Dizin taraması (ffuf/gobuster)
5. Parameter fuzzing
6. Input noktalarını bul ve test et:
   ├── SQL Injection
   ├── XSS
   ├── SSTI
   ├── Command Injection
   ├── LFI/RFI
   ├── SSRF
   ├── XXE
   ├── File upload
   ├── IDOR
   └── Auth bypass
7. Kaynak kod varsa → white-box analiz
8. Cookie/session manipülasyonu
9. Race condition
10. Business logic bug'ları
```

### 💀 PWN
```
1. file ve checksec ile analiz
2. strings ile hızlı ipucu arama
3. Binary'yi çalıştır, davranışını gözlemle
4. Ghidra/radare2 ile decompile
5. Zafiyet noktasını bul:
   ├── Buffer overflow (gets, scanf, strcpy, read)
   ├── Format string (printf user input)
   ├── Integer overflow
   ├── Use-after-free
   └── Double free
6. Güvenlik kontrollerine göre exploit stratejisi:
   ├── NX off → Shellcode injection
   ├── NX on, no PIE → ROP / ret2libc
   ├── PIE on → Address leak gerekli
   ├── Canary → Canary leak
   └── Full protection → Birden fazla teknik kombine
7. pwntools ile exploit yaz
8. Lokal test → remote exploit
```

### 🔄 REVERSE ENGINEERING
```
1. file ile dosya tipi belirle
2. strings ile flag pattern, ipuçları ara
3. Tipi göre decompile:
   ├── ELF → Ghidra, radare2
   ├── PE → Ghidra, x64dbg
   ├── .NET → dnSpy, ILSpy
   ├── Java → jadx, JD-GUI
   ├── Python → uncompyle6, pycdc
   └── APK → jadx, apktool
4. Main/entry point bul
5. Kontrol akışını takip et
6. Flag oluşturma/kontrol mantığını anla
7. Gerekirse:
   ├── Anti-debug bypass
   ├── Obfuscation çöz
   ├── Angr/Z3 ile sembolik çözüm
   └── GDB ile dinamik analiz
8. Flag'i reconstruct et
```

### 🔐 CRYPTO
```
1. Verilen verileri tanımla (ciphertext, key, parameters)
2. Cipher tipini belirle
3. Tipi göre saldırı:
   ├── Substitution → Frekans analizi, quipqiup.com
   ├── Caesar/ROT → Brute-force (26 deneme)
   ├── Vigenere → Key uzunluğu bul (Kasiski), frekans analizi
   ├── XOR → Key brute-force, known plaintext
   ├── RSA → factordb, Wiener, Hastad, common modulus
   ├── AES-ECB → Block manipulation
   ├── AES-CBC → Bit-flipping, padding oracle
   ├── Custom cipher → Analiz et ve kır
   └── Hash → Rainbow table, hashcat, john
4. CyberChef ile hızlı denemeler
5. SageMath/Z3 ile matematiksel çözüm
```

### 🔬 FORENSICS
```
1. file ile dosya tipi
2. xxd/hexdump ile magic bytes
3. exiftool ile metadata
4. strings ile ipuçları
5. binwalk ile gömülü dosya kontrolü
6. Dosya tipine göre:
   ├── Resim → steghide, zsteg, stegsolve, LSB analiz
   ├── Audio → spektrogram (Audacity), Morse, DTMF
   ├── PCAP → Wireshark/tshark, dosya çıkarma, stream takip
   ├── Memory → Volatility (pslist, filescan, hashdump)
   ├── Disk → autopsy, sleuthkit, silinmiş dosya kurtarma
   ├── ZIP → fcrackzip, john, known plaintext
   ├── PDF → pdftotext, gömülü JavaScript/'streams
   └── Git → reflog, dangling objects, diff
7. File carving: foremost, photorec
8. Bozuk dosya onarımı (header düzeltme)
```

### 🌍 OSINT
```
1. Verilen bilgiyi tanımla (resim, isim, kullanıcı adı, domain)
2. Resim → 
   ├── exiftool (GPS, tarih)
   ├── Reverse image search (Google, TinEye, Yandex)
   ├── Geolocation (sokak tabelaları, landmark'lar)
   └── Yansıma/gölge analizi
3. Kullanıcı adı →
   ├── sherlock ile platform tarama
   ├── Social media profilleri
   └── Wayback Machine
4. Domain →
   ├── WHOIS historical
   ├── DNS history
   └── Archive.org snapshots
5. Email →
   ├── hunter.io
   ├── Breach database kontrolü
   └── PGP key server
```

### 🎲 MISC
```
1. Challenge'ı dikkatlice oku — kelime oyunu olabilir
2. Encoding/decoding dene (base64, hex, binary, morse, braille)
3. Steganografi kontrol et
4. Programming challenge ise → script yaz
5. Networking challenge ise → nc ile bağlan
6. Forensics'e benziyor ama farklıysa → yaratıcı ol
7. Bazen cevap challenge açıklamasında olur
```

## Flag Extraction

### Pattern Matching
Her çözüm adımında flag pattern'lerini ara:
```bash
grep -rEo "[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*().,\-]+\}" *
grep -rEi "flag\{|ctf\{|FLAG\{|HTB\{|THM\{|pico\{|CSAW\{|DUCTF\{" *
```

### Yaygın Flag Formatları
```
flag{...}
FLAG{...}
CTF{...}
ctf{...}
HTB{...}       # HackTheBox
THM{...}       # TryHackMe
picoCTF{...}   # PicoCTF
CSAW{...}      # CSAW CTF
DUCTF{...}     # Down Under CTF
b01lers{...}   # b01lers CTF
Custom format  # Challenge'a özel
```

### Gizli Flag Kontrolü
- Base64 encoded flag
- Hex encoded flag
- ROT13 flag
- Binary encoded flag
- Resim içinde gizli (steganografi)
- Network trafiğinde gizli
- Memory dump'ta gizli
- Dosya metadata'sında gizli

## Iteratif Çözüm Stratejisi

```
Deneme 1 başarısız → Neden başarısız olduğunu analiz et
├── Yanlış kategori mi? → Tekrar kategorilen
├── Yanlış araç mı? → Farklı araç dene
├── Yanlış teknik mi? → Farklı saldırı vektörü
├── Eksik bilgi mi? → Daha fazla enumeration
└── Beklenmedik koruma mı? → Bypass tekniği araştır

Deneme 2 başarısız → Daha yaratıcı düşün
├── Hint'leri tekrar oku (challenge açıklaması, dosya adları)
├── Challenge adında kelime oyunu var mı?
├── Standart dışı teknikleri dene
└── Birden fazla tekniği kombine et

Deneme 3+ → Adım geri at
├── Basit bir şeyi mi kaçırıyorsun?
├── Overthinking yapıyor olabilirsin
├── strings, file, exiftool ile baştan başla
└── Google'da benzer challenge writeup'ları araştır
```

## Writeup Şablonu

Challenge çözüldükten sonra otomatik writeup oluştur:

```markdown
# [Challenge Adı] — [Kategori] [Puan]

## Açıklama
[Challenge açıklaması]

## Çözüm

### Adım 1: İlk Analiz
[Ne yaptın, ne buldun]

### Adım 2: Zafiyet/Çözüm Yolu Tespiti
[Hangi zafiyet/teknik bulundu]

### Adım 3: Exploitation/Çözüm
[Adım adım çözüm]
[Komutlar ve çıktıları]

### Flag
`flag{...}`

## Kullanılan Araçlar
- [araç listesi]

## Öğrenilen Dersler
- [bu challenge'dan ne öğrendin]
```

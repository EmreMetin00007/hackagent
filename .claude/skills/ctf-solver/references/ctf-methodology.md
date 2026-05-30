# CTF Metodoloji Detaylı Referans

Bu doküman her CTF kategorisi için adım adım karar ağaçları ve çözüm prosedürleri içerir.
`ctf-solver` skill'inden referans olarak kullanılır.

## Evrensel İlk Adım — Her Challenge İçin

```bash
# 1. Dosya varsa analiz et
file challenge_file
xxd challenge_file | head -20
strings challenge_file | head -50
strings -el challenge_file | head -30  # wide strings
exiftool challenge_file 2>/dev/null
binwalk challenge_file

# 2. Flag pattern ara
strings challenge_file | grep -iE "flag\{|ctf\{|HTB\{|THM\{|pico"
grep -rEo "[A-Za-z0-9_]+\{[A-Za-z0-9_!@#\$%^&*()\.,\-]+\}" challenge_file

# 3. Encoding kontrolü
echo "metin" | base64 -d 2>/dev/null
echo "metin" | xxd -r -p 2>/dev/null
```

---

## WEB — Detaylı Karar Ağacı

```
Web Challenge
│
├── Kaynak kodu verilmiş mi?
│   ├── EVET → White-box analiz
│   │   ├── Dil/framework tespit et (Flask, Express, PHP, Django, Spring)
│   │   ├── Input handling'i incele
│   │   ├── SQL sorguları → SQLi
│   │   ├── Template rendering → SSTI
│   │   ├── system()/exec()/popen() → Command Injection
│   │   ├── file_get_contents()/open() → SSRF/LFI
│   │   ├── unserialize()/pickle.loads() → Deserialization
│   │   ├── eval()/exec() → Code Injection
│   │   ├── JWT handling → JWT attacks
│   │   ├── Cookie/session → Session attacks
│   │   └── Race condition potansiyeli
│   │
│   └── HAYIR → Black-box analiz
│       ├── Teknoloji fingerprint (whatweb, response headers)
│       ├── Dizin taraması (ffuf/gobuster)
│       ├── robots.txt, sitemap.xml, .git/
│       ├── Her input noktasını bul
│       └── Fuzzing ile zafiyet ara
│
├── Login sayfası var mı?
│   ├── Default credentials dene (admin:admin, admin:password)
│   ├── SQLi auth bypass
│   ├── Registration açık mı → kayıt ol, privilege escalation dene
│   ├── Password reset → IDOR, token predictability
│   └── JWT/cookie manipülasyonu
│
├── Dosya upload var mı?
│   ├── Extension bypass (.php → .phtml, .php5, .phar)
│   ├── MIME type bypass
│   ├── Magic bytes (GIF89a prefix)
│   ├── Double extension (.php.jpg)
│   ├── Null byte (.php%00.jpg)
│   └── Path traversal (../../shell.php)
│
├── API endpoint var mı?
│   ├── Parameter fuzzing
│   ├── IDOR (id değiştir)
│   ├── HTTP method değiştir (GET→POST, PUT, DELETE)
│   ├── Content-Type değiştir (JSON→XML → XXE)
│   ├── GraphQL introspection
│   └── Rate limiting bypass
│
└── Hiçbiri çalışmadı?
    ├── Header manipulation (X-Forwarded-For, X-Original-URL)
    ├── HTTP Request Smuggling
    ├── Race condition
    ├── Cache poisoning
    ├── WebSocket test
    └── Challenge açıklamasını tekrar oku — kelime oyunu olabilir
```

---

## PWN — Detaylı Karar Ağacı

```
Binary alındı
│
├── checksec çıktısı
│   ├── No canary + No NX + No PIE
│   │   └── Klasik shellcode injection
│   │       1. Offset bul
│   │       2. Shellcode yaz/hazır kullan
│   │       3. NOP sled + shellcode + ret addr
│   │
│   ├── NX enabled + No canary + No PIE
│   │   └── ROP/ret2libc
│   │       1. Offset bul
│   │       2. Gadget'ları bul (ROPgadget)
│   │       3. system("/bin/sh") zinciri kur
│   │
│   ├── NX + Canary + No PIE
│   │   └── Canary leak + ROP
│   │       1. Format string ile canary leak
│   │       2. Canary'yi payload'a ekle
│   │       3. ROP chain
│   │
│   ├── NX + Canary + PIE
│   │   └── Full bypass
│   │       1. Info leak (format string, partial overwrite)
│   │       2. PIE base hesapla
│   │       3. Canary leak
│   │       4. Libc leak
│   │       5. Exploit
│   │
│   └── Full RELRO + All protections
│       └── Karmaşık teknik gerekli
│           - Heap exploitation
│           - FSOP (File Stream Oriented Programming)
│           - Stack pivot
│           - Sigreturn Oriented Programming
│
├── Zafiyet tipi
│   ├── gets/scanf/read → Buffer Overflow
│   │   1. Pattern ile offset bul
│   │   2. Korumalara göre exploit
│   │
│   ├── printf(user_input) → Format String
│   │   1. Offset bul (%X$x)
│   │   2. Canary/PIE/libc leak
│   │   3. Write (GOT overwrite veya return addr)
│   │
│   ├── malloc/free pattern → Heap
│   │   1. Heap layoutıanaliz et
│   │   2. UAF/Double Free/Overflow
│   │   3. Tcache/Fastbin attack
│   │
│   └── Integer overflow → Size kontrolü bypass
│       1. Negatif sayı/overflow noktası bul
│       2. Buffer sınırını bypass et
│
└── Remote exploit
    1. Lokal PoC'yi doğrula
    2. Remote offset'ler farklı olabilir
    3. ASLR: brute force veya leak
    4. pwntools remote() ile bağlan
```

---

## CRYPTO — Detaylı Karar Ağacı

```
Şifreli metin alındı
│
├── Ne tip veri?
│   ├── Kısa metin (< 100 karakter)
│   │   ├── Sadece harfler → Substitution (Caesar, ROT, Vigenere, Atbash)
│   │   ├── Harfler + sayılar → Base64/Base32/Hex
│   │   ├── Sadece 0 ve 1 → Binary
│   │   ├── Nokta ve tire → Morse code
│   │   ├── Kabartma pattern → Braille
│   │   ├── Emoji/garip karakter → Esoteric encoding
│   │   └── =ile biter → Base64 (padding)
│   │
│   ├── Büyük sayılar (n, e, c)
│   │   └── RSA
│   │       ├── n küçük → factordb.com
│   │       ├── e küçük (e=3) → Hastad/cube root
│   │       ├── e büyük → Wiener attack
│   │       ├── Çoklu (n,c) → Common modulus / CRT
│   │       ├── p ve q yakın → Fermat factorization
│   │       ├── n paylaşılıyor → GCD(n1,n2)
│   │       └── dp/dq leak → Partial key recovery
│   │
│   ├── Hex bloklar (16/32 byte)
│   │   └── AES
│   │       ├── Tekrarlayan bloklar → ECB mode
│   │       ├── IV + ciphertext → CBC
│   │       ├── Padding error oracle → Padding Oracle Attack
│   │       └── Bilinen plaintext → Known plaintext attack
│   │
│   └── Hash değeri
│       ├── 32 char hex → MD5
│       ├── 40 char hex → SHA-1
│       ├── 64 char hex → SHA-256
│       ├── 128 char hex → SHA-512
│       ├── $1$ prefix → MD5crypt
│       ├── $2$ prefix → bcrypt
│       ├── $6$ prefix → SHA-512crypt
│       └── hashcat/john ile kır
│
├── Otomatik dene
│   ├── ciphey -t "text" (otomatik çözücü)
│   ├── CyberChef Magic operation
│   ├── dCode.fr (online cipher identifier)
│   └── quipqiup.com (substitution solver)
│
└── Custom cipher
    ├── Frekans analizi (harflerin dağılımı)
    ├── Key pattern analizi
    ├── Known plaintext (flag{ prefix)
    ├── Brute force (key space küçükse)
    └── Z3 constraint solver
```

---

## FORENSICS — Detaylı Karar Ağacı

```
Dosya alındı
│
├── file komutu çıktısı
│   ├── PNG/JPEG/BMP/GIF → Resim Steganografi
│   │   ├── exiftool → Metadata (GPS, comment, author)
│   │   ├── strings → Gömülü metin
│   │   ├── binwalk → Gömülü dosyalar
│   │   ├── steghide extract → JPEG/BMP gizli veri
│   │   ├── zsteg → PNG LSB steg
│   │   ├── stegsolve → Bit plane analizi
│   │   ├── Pixel LSB manual → Custom steg
│   │   ├── Boyut kontrolü → Dosya boyutu normalden büyükse ek veri var
│   │   ├── IHDR chunk → PNG boyut manipülasyonu (yükseklik artır)
│   │   └── Palette/color manipulation
│   │
│   ├── WAV/MP3/FLAC → Audio
│   │   ├── Spektrogram → Audacity/Sonic Visualiser
│   │   ├── Morse code → CW decoder
│   │   ├── DTMF tones → DTMF decoder
│   │   ├── LSB audio → stegolsb
│   │   ├── Ters çalma → Audacity reverse
│   │   └── Slow/fast → Speed değiştir
│   │
│   ├── PCAP/PCAPNG → Network Capture
│   │   ├── Wireshark/tshark ile aç
│   │   ├── Protocol hierarchy → en çok kullanılan protokol
│   │   ├── HTTP → dosya çıkar, POST data, credentials
│   │   ├── DNS → exfiltration, covert channel
│   │   ├── FTP → credentials, transfer edilen dosyalar
│   │   ├── SMB → paylaşılan dosyalar
│   │   ├── TCP stream follow → konuşma reconstruction
│   │   ├── ICMP → covert channel (data in ping)
│   │   ├── TLS → key varsa decrypt
│   │   └── USB → keystroke capture
│   │
│   ├── ELF/PE → Binary (pwn/reverse'e yönlendir)
│   │
│   ├── ZIP/RAR/7z/GZ → Archive
│   │   ├── Şifreli → fcrackzip/john/hashcat
│   │   ├── Known plaintext → bkcrack
│   │   ├── CRC32 → kısa dosyalar brute force
│   │   ├── Fake encryption → zip -e0
│   │   └── Recursive zip → script ile çıkar
│   │
│   ├── PDF → Document
│   │   ├── pdftotext → metin çıkar
│   │   ├── pdf-parser → obje analizi
│   │   ├── JavaScript → malware analizi
│   │   ├── Gömülü dosyalar → binwalk, foremost
│   │   └── Metadata → exiftool
│   │
│   ├── Memory dump → Memory Forensics
│   │   ├── volatility imageinfo → profil tespiti
│   │   ├── pslist/pstree → çalışan process'ler
│   │   ├── cmdline → komut satırı argümanları
│   │   ├── filescan → dosya listesi
│   │   ├── dumpfiles → dosya çıkarma
│   │   ├── hashdump → şifre hash'leri
│   │   ├── netscan → ağ bağlantıları
│   │   ├── clipboard → clipboard içeriği
│   │   ├── screenshot → ekran görüntüleri
│   │   ├── consoles → konsol geçmişi
│   │   └── malfind → malware tespiti
│   │
│   ├── Disk image → Disk Forensics
│   │   ├── fdisk/mmls → partition tablosu
│   │   ├── mount → erişim
│   │   ├── fls → dosya listesi (silinmişler dahil)
│   │   ├── icat → dosya çıkarma
│   │   ├── autopsy → GUI analiz
│   │   ├── testdisk → kurtarma
│   │   └── extundelete → ext dosya kurtarma
│   │
│   ├── Git repo → Git Forensics
│   │   ├── git log --all → tüm commitler
│   │   ├── git reflog → silinmiş commitler
│   │   ├── git stash list → stash'ler
│   │   ├── git fsck → dangling objects
│   │   ├── git diff → farklar
│   │   └── git log -S "keyword" → içerik araması
│   │
│   └── Bilinmeyen → 
│       ├── xxd → magic bytes kontrol
│       ├── Header düzeltme (bozuk dosya)
│       ├── binwalk -e → gömülü dosya çıkar
│       ├── foremost → file carving
│       └── strings → her şeyi dene
```

---

## Hızlı Çözüm Tablosu

| İpucu/Durum | Muhtemel Teknik |
|-------------|-----------------|
| "Invisible" / "Hidden" | Steganografi, beyaz metin, LSB |
| "History" / "Past" | Git forensics, Wayback, log analiz |
| "Listen" / "Sound" | Audio steg, spektrogram, Morse |
| "Memory" / "Remember" | Memory dump / Volatility |
| "Network" / "Capture" | PCAP analizi |
| "Key" / "Lock" | Crypto, RSA, AES |
| "Overflow" / "Buffer" | Binary overflow exploit |
| "Inject" / "Input" | SQLi, XSS, CMDi, SSTI |
| "Include" / "File" | LFI/RFI |
| "Request" / "Fetch" | SSRF |
| "Cookie" / "Session" | Session hijacking, JWT |
| "Upload" | File upload + RCE |
| "Race" | Race condition |
| "Serial" | Deserialization |
| "Template" | SSTI |
| Dosya boyutu normalden büyük | Gömülü dosya/steg |
| Resim bozuk görünüyor | Header düzeltme, boyut manipülasyonu |
| Çok sayıda dosya | Otomatik script gerekli |

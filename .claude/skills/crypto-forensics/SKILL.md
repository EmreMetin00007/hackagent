---
name: crypto-forensics
description: "Kriptografi analizi ve dijital forensics skill'i. Şifreleme kırma, hash cracking, steganografi, memory forensics, PCAP analizi, disk forensics, dosya kurtarma ve tüm crypto/forensics teknikleri. Bu skill'i şu durumlarda kullan: kullanıcı 'şifre kır', 'hash crack', 'steganografi', 'gizli veri', 'forensics', 'memory dump', 'PCAP analiz', 'Wireshark', 'Volatility', 'disk image', 'dosya kurtar', 'encoding', 'decoding', 'base64', 'XOR', 'RSA', 'AES', 'cipher', 'crypto', 'frekans analizi', 'binwalk', 'foremost', 'exiftool', 'metadata', 'CyberChef' dediğinde veya şifreli/gizli verinin analizi istendiğinde. Herhangi bir kriptografi kırma, dijital forensics veya veri kurtarma görevi olduğunda mutlaka bu skill'i kullan."
---

# 🔐 Kriptografi & Dijital Forensics

Şifreleme/encoding analizi, hash kırma, steganografi, memory/disk/network forensics için kapsamlı skill.

## KRIPTOGRAFI

### Cipher Tanımlama

**Otomatik Tanımlama:**
```bash
# CyberChef Magic Operation (web tabanlı)
# https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')

# ciphey — otomatik cipher çözücü
ciphey -t "şifreli_metin"
ciphey -f encrypted_file.txt
```

**Manuel Tanımlama İpuçları:**
```
Sadece harfler → Substitution cipher (Caesar, Vigenere, ROT)
Sadece 0 ve 1 → Binary encoding
Sadece hex karakterler (0-9, a-f) → Hex encoding
Base64 karakterler (A-Za-z0-9+/=) → Base64
URL encoded (%XX) → URL encoding
= ile biter → Muhtemelen Base64 veya Base32
Tekrarlayan pattern → ECB mode AES
Büyük sayılar → RSA
```

### Encoding / Decoding
```bash
# Base64
echo "encoded_text" | base64 -d
echo "text" | base64

# Base32
echo "encoded_text" | base32 -d

# Hex
echo "hex_string" | xxd -r -p
echo "text" | xxd -p

# URL Encoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('encoded'))"
python3 -c "import urllib.parse; print(urllib.parse.quote('text'))"

# ROT13
echo "text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Binary
python3 -c "print(''.join(chr(int(b,2)) for b in 'binary_str'.split()))"

# Morse Code
# .- → A, -... → B, vs.

# Brainfuck interpreter
# Online: https://copy.sh/brainfuck/

# Çoklu encoding (zincirleme)
echo "text" | base64 | xxd -p  # base64 → hex
```

### Hash Cracking
```bash
# Hash tipi tanımlama
hashid 'HASH_VALUE'
hash-identifier

# hashcat ile kırma
hashcat -m HASH_MODE 'HASH' /usr/share/wordlists/rockyou.txt
hashcat -m HASH_MODE 'HASH' /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule

# Yaygın hash modları:
# 0     = MD5
# 100   = SHA1
# 1400  = SHA-256
# 1700  = SHA-512
# 500   = MD5crypt ($1$)
# 1800  = sha512crypt ($6$)
# 3200  = bcrypt ($2*$)
# 1000  = NTLM
# 5500  = NetNTLMv1
# 5600  = NetNTLMv2
# 13100 = Kerberoasting
# 16500 = JWT
# 11300 = Bitcoin wallet
# 22000 = WPA-PBKDF2-PMKID+EAPOL

# john the ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
john --show hash.txt  # Kırılmış hash'leri göster

# Online hash lookup
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
```

### RSA Saldırıları
```python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse
import sympy

# Public key'den bilgi çıkarma
key = RSA.import_key(open('public.pem').read())
n = key.n  # modulus
e = key.e  # public exponent
print(f"n = {n}")
print(f"e = {e}")
print(f"n bit length = {n.bit_length()}")

# --- Saldırı 1: Küçük n — factordb.com'da ara ---
# http://www.factordb.com/index.php?query=N_VALUE
# veya: sympy.factorint(n)

# --- Saldırı 2: Wiener Attack (küçük d) ---
# e çok büyükse d küçük olabilir
# pip3 install owiener
import owiener
d = owiener.attack(e, n)
if d:
    plaintext = pow(ciphertext, d, n)
    print(long_to_bytes(plaintext))

# --- Saldırı 3: Hastad Attack (küçük e, çoklu n) ---
# e=3 ve 3 farklı n,c çifti varsa → CRT ile çöz
from sympy.ntheory.modular import crt
m_cubed, _ = crt([n1, n2, n3], [c1, c2, c3])
m = sympy.integer_nthroot(m_cubed, 3)[0]
print(long_to_bytes(m))

# --- Saldırı 4: Common Modulus Attack ---
# Aynı n, farklı e ile şifrelenmiş aynı mesaj
# Bezout identity ile d1, d2 bul
from math import gcd
def common_modulus(n, e1, e2, c1, c2):
    g, a, b = extended_gcd(e1, e2)
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return long_to_bytes(m)

# --- Saldırı 5: Fermat Factorization (p ve q yakınsa) ---
def fermat_factor(n):
    a = sympy.integer_nthroot(n, 2)[0] + 1
    b2 = a*a - n
    while not sympy.perfect_power(b2):
        a += 1
        b2 = a*a - n
    b = sympy.integer_nthroot(b2, 2)[0]
    return a - b, a + b

# p, q bulunduktan sonra decrypt
p, q = fermat_factor(n)
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
plaintext = pow(ciphertext, d, n)
print(long_to_bytes(plaintext))
```

### AES Saldırıları
```python
# ECB Mode — Block reordering
# Aynı plaintext block → aynı ciphertext block
# Block'ları yeniden sıralayarak manipülasyon

# CBC Bit-Flipping
# IV veya önceki ciphertext block'ta bit değiştirerek
# sonraki block'taki plaintext'i manipüle et
iv_modified = bytearray(iv)
iv_modified[target_pos] ^= ord(original_char) ^ ord(desired_char)

# Padding Oracle Attack
# padbuster veya custom script ile
# Her byte için 256 deneme yaparak decrypt et

# Known Plaintext
# Açık metin biliniyorsa key recovery
```

### XOR Analizi
```python
# Tek byte XOR brute-force
for key in range(256):
    result = bytes([b ^ key for b in ciphertext])
    if result.isascii():
        print(f"Key {key}: {result}")

# Repeating key XOR
# 1. Key uzunluğunu bul (Hamming distance)
# 2. Her key byte'ını ayrı ayrı kır (frekans analizi)

# XOR ile iki şifreli metin → key kurtarma
# c1 XOR c2 = p1 XOR p2 (crib dragging)
```

### Z3 Constraint Solver
```python
from z3 import *

# Kısıt tabanlı çözüm
s = Solver()
x = BitVec('x', 32)
y = BitVec('y', 32)

# Kısıtları ekle
s.add(x + y == 100)
s.add(x * 2 == y)

if s.check() == sat:
    m = s.model()
    print(f"x = {m[x]}, y = {m[y]}")
```

---

## DİJİTAL FORENSICS

### Dosya Analizi
```bash
# Dosya tipi
file dosya.bin
xxd dosya.bin | head -20  # Hex dump
hexdump -C dosya.bin | head -20

# Magic bytes kontrolü
# PNG: 89 50 4E 47 → \x89PNG
# JPEG: FF D8 FF
# GIF: 47 49 46 38 → GIF8
# PDF: 25 50 44 46 → %PDF
# ZIP: 50 4B 03 04 → PK
# ELF: 7F 45 4C 46 → \x7fELF
# PE: 4D 5A → MZ

# Metadata
exiftool dosya.jpg
exiftool -all dosya.pdf

# Strings
strings dosya.bin
strings -el dosya.bin  # Unicode
strings -n 20 dosya.bin  # Minimum 20 karakter
```

### Steganografi
```bash
# Genel araçlar
binwalk dosya.png          # Gömülü dosya analizi
binwalk -e dosya.png       # Gömülü dosyaları çıkar
foremost dosya.png         # File carving
foremost -i disk.img -o output/

# Resim steganografisi
steghide info dosya.jpg
steghide extract -sf dosya.jpg -p "password"
steghide extract -sf dosya.jpg  # Şifresiz

zsteg dosya.png            # PNG/BMP steanaliz
zsteg -a dosya.png         # Tüm kontroller

stegsolve                  # Görsel analiz (Java GUI)
# Bit plane analizi, color filter, data extraction

# LSB steganografi — manual
python3 -c "
from PIL import Image
img = Image.open('image.png')
pixels = list(img.getdata())
bits = ''.join(str(p[0] & 1) for p in pixels[:1000])
text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(text)
"

# Audio steganografi
# Spektrogram analizi → Audacity veya Sonic Visualiser
# DTMF tone decoding
# Morse code in audio
```

### Memory Forensics (Volatility)
```bash
# Volatility 3
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist          # Process listesi
vol3 -f memory.dmp windows.pstree          # Process ağacı
vol3 -f memory.dmp windows.cmdline         # Komut satırı argümanları
vol3 -f memory.dmp windows.filescan        # Dosya listesi
vol3 -f memory.dmp windows.dumpfiles --pid PID  # Dosya dump
vol3 -f memory.dmp windows.hashdump        # Password hash dump
vol3 -f memory.dmp windows.netscan         # Network bağlantıları
vol3 -f memory.dmp windows.registry.hivelist   # Registry hive'ları
vol3 -f memory.dmp windows.malfind         # Malware detection
vol3 -f memory.dmp windows.handles --pid PID   # Handle'lar

# Volatility 2 (eski ama hala kullanışlı)
volatility -f memory.dmp imageinfo         # Profil tespiti
volatility -f memory.dmp --profile=PROFIL pslist
volatility -f memory.dmp --profile=PROFIL filescan
volatility -f memory.dmp --profile=PROFIL dumpfiles -Q OFFSET -D output/
volatility -f memory.dmp --profile=PROFIL hashdump
volatility -f memory.dmp --profile=PROFIL clipboard
volatility -f memory.dmp --profile=PROFIL screenshot -D output/
volatility -f memory.dmp --profile=PROFIL consoles
volatility -f memory.dmp --profile=PROFIL envars

# Linux memory
vol3 -f memory.lime linux.pslist
vol3 -f memory.lime linux.bash             # Bash history
```

### Network Forensics (PCAP Analizi)
```bash
# tshark — CLI Wireshark
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
tshark -r capture.pcap -Y "tcp.port==21" -z follow,tcp,ascii,0
tshark -r capture.pcap -Y "ftp.request.command==PASS" -T fields -e ftp.request.arg

# Dosya çıkarma
tshark -r capture.pcap --export-objects http,exported_files/
tshark -r capture.pcap --export-objects smb,exported_files/

# Wireshark filtre örnekleri
# ip.addr == 192.168.1.1
# tcp.port == 80
# http.request.method == "POST"
# dns.qry.name contains "flag"
# frame contains "password"
# tcp.stream eq 0  (belli bir TCP stream)

# Network Miner — otomatik PCAP analiz
networkminer capture.pcap

# tcpflow — TCP stream reconstruction
tcpflow -r capture.pcap

# Scapy ile custom analiz
python3 -c "
from scapy.all import *
packets = rdpcap('capture.pcap')
for pkt in packets:
    if pkt.haslayer(Raw):
        print(pkt[Raw].load)
"
```

### Disk Forensics
```bash
# Disk image bilgisi
fdisk -l disk.img
mmls disk.img

# Mount etme
mount -o loop,ro disk.img /mnt/forensic
mount -o loop,ro,offset=OFFSET disk.img /mnt/forensic

# Sleuth Kit
fls -r disk.img           # Dosya listesi (silinmişler dahil)
icat disk.img INODE        # Dosya içeriği (inode ile)
blkls disk.img             # Unallocated blocks

# Autopsy — GUI forensic platform
autopsy

# File carving
photorec disk.img
scalpel -c /etc/scalpel/scalpel.conf -o output/ disk.img

# Silinmiş dosya kurtarma
extundelete --restore-all disk.img
testdisk disk.img
```

### Log Analizi
```bash
# Apache/Nginx erişim logları
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn  # IP frekans
cat access.log | grep "POST" | grep -i "login"  # Login denemeleri
cat access.log | grep "404\|403\|500"  # Error'lar
cat access.log | grep -i "union\|select\|script\|../\|etc/passwd"  # Saldırı pattern

# Auth logları
cat auth.log | grep "Failed password"  # Başarısız login
cat auth.log | grep "Accepted"  # Başarılı login

# Windows Event Log
# evtx_dump.py ile parse et
python3 evtx_dump.py Security.evtx | grep "4624\|4625\|4672"
# 4624 = Successful login
# 4625 = Failed login
# 4672 = Special privileges assigned
```

### Git Forensics
```bash
# Commit geçmişi
git log --all --oneline
git log --all --diff-filter=D --name-only  # Silinen dosyalar
git log -p  # Tüm diff'ler

# Tüm branch'lar
git branch -a

# Stash
git stash list
git stash show -p stash@{0}

# Reflog — silinmiş commit'ler dahil
git reflog

# Commit içeriği
git show COMMIT_HASH
git diff COMMIT1 COMMIT2

# Git objects — dangling objects
git fsck --unreachable
git show DANGLING_HASH

# Dosya geçmişi
git log --follow -p -- dosya.txt

# Arama
git log --all -S "password"  # İçerikte ara
git log --all --grep="secret"  # Commit mesajında ara
```

### ZIP/Archive Forensics
```bash
# ZIP password cracking
fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt archive.zip
john --format=zip hash.txt --wordlist=rockyou.txt
zip2john archive.zip > hash.txt

# RAR
rar2john archive.rar > hash.txt
john hash.txt --wordlist=rockyou.txt

# 7z
7z2john archive.7z > hash.txt

# ZIP plaintext attack (bkcrack)
bkcrack -C encrypted.zip -c known_file.txt -P plaintext.zip -p known_file.txt
```

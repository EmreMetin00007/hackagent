# 🧪 TryHackMe'de Orkestratör Akışı Deneme Rehberi (Kali)

Amaç: `deep_think` orkestratörünün gerçek session'da garanti tetiklendiğini doğrula —
**deep_think → step_0 kickoff slash-command → kill-chain → doğrula → skorla → öğren.**

> ⚖️ **Yetki:** TryHackMe odaları AÇIKÇA test için yetkilidir (yasal lab). Yalnızca
> sana atanan THM hedef IP'sine dokun. Scope = o tek IP.

---

## 0) Ön koşullar (bir kere)

```bash
# CCO kurulu mu + MCP server'lar sağlıklı mı?
cd ~/cco           # CCO repo dizinin
source .env        # OPENROUTER_API_KEY veya DEEPSEEK_API_KEY + model seçimleri
claude             # REPL aç
> /health          # tüm MCP server'lar UP olmalı (özellikle reasoning, validator, kali-tools)
> /tools           # reasoning altında: deep_think, recommend_skills, compose_attack_chains...
                   # (reasoning = 14 tool görmelisin)
```

THM VPN'e bağlan ve hedef IP'yi al:
```bash
sudo openvpn ~/Downloads/<thm-kullanıcı>.ovpn &     # THM "Access" sayfasından indirilen .ovpn
# Oda sayfasından "Start Machine" → hedef IP (örn. 10.10.11.42)
ping -c1 10.10.11.42                                  # erişim doğrula
```

---

## 1) Önerilen ilk odalar (router'ın farklı skill seçtiğini gör)

| Oda | Beklenen kickoff skill | Neyi gösterir |
|---|---|---|
| **Vulnversity** | `/recon-enumeration` → `/web-exploit` | recon→file upload→RCE zinciri |
| **RootMe** | `/web-exploit` | upload→webshell→RCE kill-chain |
| **Pickle Rick** | `/web-exploit` | command_injection→RCE |
| **OWASP Top 10 / Juice Shop** | `/web-advanced` | jwt/idor/oauth → ATO zinciri |
| **Basic Pentesting** | `/recon-enumeration` | servis enum → zayıf cred → admin |

İlk denemen için **web odalı bir oda** seç (router + kill-chain en görünür orada).

---

## 2) Akış — iki paslı (gerçekçi)

Taze hedefte memory boştur → `deep_think` önce **recon** önerir, kill-chain ancak
bulgular kaydedildikten sonra oluşur. Bu yüzden iki pas:

### Pas 1 — Orkestratör + keşif
```text
> /deep-reasoning 10.10.11.42 scope: 10.10.11.42
```
Çıktıda şunları DOĞRULA (orkestratör tetiklendi mi?):
- `step_0_recommended_skills.kickoff`  → örn. `/recon-enumeration 10.10.11.42`  ✅
- `phase: fresh-recon`  (memory boş)  ✅
- `pipeline` ve 5 adımlı `next_steps`  ✅

Sonra **kickoff komutunu AYNEN çalıştır** (skill garanti tetiklenir):
```text
> /recon-enumeration 10.10.11.42
```
Bu, nmap/enum tool'larını çalıştırır. Bulguları memory'ye yaz (skill otomatik yapar;
yapmazsa elle):
```text
> mcp__memory-server__store_endpoint(target="10.10.11.42", url_or_port="80", technologies="apache php")
> mcp__memory-server__store_finding(target="10.10.11.42", type="File Upload", severity="high", description="/upload.php filtre zayıf")
```

### Pas 2 — Zincir → doğrula → skorla → exploit → öğren
Şimdi memory dolu; `deep_think`'i TEKRAR çağır:
```text
> /deep-reasoning 10.10.11.42 scope: 10.10.11.42
```
Bu sefer DOĞRULA:
- `step_2b_kill_chains.chains_found > 0` ve `best_chain` (örn. `file_upload → webshell → remote_code_execution`)  ✅
- `step_2b_kill_chains.best_chain_report` → adım adım Markdown trace (validator komutlu)  ✅
- `step_5_exploitability_preview.band` → validator yokken `POSSIBLE` (CONFIRMED değil)  ✅

best_chain'i yürü (her adım için):
```text
# 1) DOĞRULA (deterministik oracle)
> mcp__validator__validate_finding(...)         # veya step'in validate_with'i
# 2) SKORLA (validator confidence'ı ver → band CONFIRMED mı?)
> mcp__reasoning__exploitability_score(technique="file_upload", validator_confidence=0.95, evidence="...")
# 3) CONFIRMED ise exploit
> /web-exploit 10.10.11.42/upload.php
# 4) WAF/filtre bloklarsa payload'ı evrimle
> mcp__reasoning__evolve_payload(payload="<?php system($_GET[c]);?>", technique="file_upload", blocked_by="content-type filter")
# 5) ÖĞREN
> mcp__reasoning__record_lesson(context="thm upload", technique="file_upload", action="...", outcome="rce", worked=true)
> mcp__reasoning__record_payload_result(technique="file_upload", operators="case_swap,null_byte", worked=true)
```

---

## 3) Headless (tek komut) alternatifi

```bash
# Orkestratörü doğrudan çalıştır, çıktıyı oku, sonra kickoff'u sen tetikle
claude -p "/deep-reasoning 10.10.11.42 scope: 10.10.11.42"
```

---

## 4) Başarı kriteri (bunu görürsen orkestratör çalışıyor)

- [ ] `deep_think` çıktısında **step_0 kickoff** bir `/skill <IP>` döndürdü
- [ ] Kickoff slash-command'ı skill'i tetikledi (recon/web tool'ları koştu)
- [ ] 2. pasta **step_2b kill-chain** gerçek bir zincir üretti (`...→remote_code_execution`)
- [ ] `validate_*` adımı **CONFIRMED** verdi → `exploitability_score` **CONFIRMED** banda çıktı
- [ ] `record_lesson` sonrası `lesson_stats()` win-rate'i güncelledi (beyin öğrendi)

---

## 5) Sorun giderme

| Belirti | Çözüm |
|---|---|
| `/health` server DOWN | `~/.claude.json` MCP kayıtları + `pip install` bağımlılıkları; `install-cco.sh` tekrar |
| Model `Skill` tetiklemiyor | Zaten çözümü bu: **kickoff slash-command'ı elle çalıştır** (en güvenilir) |
| `step_2b` boş | Henüz bulgu yok → önce recon + `store_finding`/`store_endpoint`, sonra deep_think tekrar |
| Reflexion atlanıyor | `DEEPSEEK_API_KEY` veya `OPENROUTER_API_KEY` set değil — EV/dersler yine çalışır |
| Maliyet | Easy oda uçtan uca ~$0.3–1.5 (model seçimine göre); `/cost` ile izle |

> Bu, README'ye koyacağın **ilk gerçek validator-onaylı kill-chain kanıtının** da
> üretildiği akıştır — `best_chain_report` Markdown'ını sakla.

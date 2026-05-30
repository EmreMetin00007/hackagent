---
name: osint-password-spraying
description: "Kurumsal OSINT, e-posta toplama ve hesabı kilitlemeden (lockout) güvenli hızda Password Spraying (Parola Püskürtme) metodolojisi."
---

# Gelişmiş OSINT ve Parola Püskürtme (Password Spraying) Metodolojisi

Hedef sistemde hiçbir zafiyet bulamadığında (veya iç ağa sızmak için VPN/O365 portalına ihtiyacın olduğunda) odaklanman gereken şey insanlardır (TA0001: Initial Access). Brute Force (Kaba Kuvvet) yapmak hesapları kilitler ve anında yakalanmana sebep olur. Bunun yerine "Password Spraying" tekniğini kullanmalısın.

## 1. Keşif ve E-posta Toplama (OSINT)
Hedef kurumun çalışanlarının e-posta adreslerini ve isim formatlarını (örn: `isim.soyisim@sirket.com` veya `isoyisim@sirket.com`) bulmalısın.

- **Eylem:** `mcp-osint-tools` içindeki `gather_emails` aracını kullan.
- **Neden:** Bu araç, Hunter.io, LinkedIn (Google Dorks) ve diğer açık kaynaklardan hedef domaine ait geçerli e-posta adreslerini toplayarak sana yapılandırılmış (JSON) bir liste sunar.

## 2. Şifre Tahmin Stratejisi (Password Profiling)
Elde ettiğin e-posta listesine saldırmadan önce mantıklı şifreler seçmelisin. Şifreler genellikle şu formatlarda olur:
- Mevsim+Yıl+ÖzelKarakter (Örn: `Yaz2026!`, `Kis2025*`)
- ŞirketAdı+KuruluşYılı (Örn: `Sirketim1990!`)
- Parola gibi şifreler (Örn: `Password123!`, `Qwerty!23`)

## 3. Password Spraying (T1110.003)
Hesapları kilitlememek (Lockout Threshold) için her hesapta *sadece bir* veya en fazla *iki* şifre denemelisin.

- **Eylem:** `mcp-osint-tools` içindeki `password_spray_structured` aracını kullan.
- **Güvenlik Kuralı:** Eğer Office 365, OWA veya VPN paneline saldırıyorsan `delay` (gecikme) parametresini mutlaka en az 5-10 saniye aralığında tut. Hedef sistem "Too Many Requests" hatası verirse, taramayı durdur ve en az 30 dakika bekle.

## 4. MFA (Multi-Factor Authentication) Kontrolü
Eğer parolayı doğru bulursan, ancak sistem 2FA kodu isterse (MFA Prompt):
- **Eylem:** Şifrenin doğru olduğunu `agent_memory.db`'ye "Geçerli Kimlik Bilgisi" olarak not al.
- Eğer hedef organizasyon SMS veya Authenticator kullanıyorsa, şifre doğru olsa bile içeri giremeyebilirsin. Bu durumda farklı protokolleri (Örn: MFA istemeyen eski protokoller - IMAP/SMTP/POP3) `ad_smb_enum` veya nmap ile tarayarak şifreyi orada dene.

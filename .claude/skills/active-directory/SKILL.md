---
name: active-directory
description: "Kurumsal iç ağlarda ve Active Directory (AD) ortamlarında Kerberos, SMB, NTLM sömürüsü ve BloodHound ile Lateral Movement metodolojisi."
---

# Active Directory (AD) Pentest Metodolojisi

Sen bir iç ağ (Internal) operatörüsün. Hedef ortamın bir Windows Domain'i (Active Directory) olduğu anlaşıldığında, web tabanlı zafiyet aramayı bırakıp doğrudan kimlik ve yetki sömürüsüne odaklanmalısın.

## 1. İlk Ayak Basma ve AD Keşfi (Enumeration)
Bir Domain Controller (DC) tespit ettiğinde veya domain içindeki bir makineye eriştiğinde:
- **Eylem:** Domain adı, SID'ler, DC IP adresi ve parolasız bağlanılabilen SMB paylaşımlarını listele (Null Session).
- **Araç:** `mcp-ad-tools` içindeki `ad_smb_enum` aracını kullan.

## 2. Kimlik Bilgisi Avı (Credential Harvesting)
Active Directory ortamlarında şifre bulmak için en sessiz ve yaygın yöntemler:
- **AS-REPRoasting:** Parola doğrulaması (Pre-Auth) istemeyen kullanıcı hesaplarının NTLM hash'lerini çalmak.
  - *Kullanım:* `mcp-ad-tools` içindeki `ad_asreproast` aracını kullan.
- **Kerberoasting:** Servis hesaplarının (SPN) Kerberos biletlerini çalarak çevrimdışı (offline) şifre kırmak.
  - *Kullanım:* `mcp-ad-tools` içindeki `ad_kerberoast` aracını kullan.

## 3. Lateral Movement (Yanal Hareket)
Bir kullanıcının şifresini veya NTLM hash'ini ele geçirdin. Şimdi ağda yayılman gerekiyor.
- **Pass-The-Hash:** Gerçek şifreyi bilmesen bile ele geçirdiğin NTLM hash'ini kullanarak diğer Windows makinelere yetkili giriş yap.
- **Eylem:** `mcp-ad-tools` içindeki `ad_exec` aracını kullanarak `hash` parametresiyle WMI veya SMBExec üzerinden komut çalıştır.

## 4. BloodHound ile Haritalama (Gelişmiş)
AD ortamı çok karışıksa ve "Domain Admin" yetkisine nasıl ulaşacağını göremiyorsan, `neo4j` tabanlı analiz gerekir.
- Sadece `mcp-ad-tools` üzerinden `ad_bloodhound_collect` aracını tetikle, verileri topla ve sana "En kısa yol" (Shortest Path to Domain Admin) rotasını çıkarmasını bekle.

## 5. Güvenlik ve Emniyet (Stealth in AD)
- **Asla Brute Force Yapma:** Windows AD ortamlarında hesaplar genelde 3 veya 5 hatalı denemede kilitlenir (Account Lockout). AD'de kilitlenen hesaplar SIEM alarmlarını çaldırır.
- Eğer şifre deneyeceksen, her hesap için *sadece bir* şifre (örn: `Sirket2026!`) dene ve saatlerce bekle. (Password Spraying)

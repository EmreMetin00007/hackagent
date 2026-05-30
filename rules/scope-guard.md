# Scope Guard — Hedef Koruma Kuralları

## Zorunlu Kurallar
1. Sadece açıkça belirtilen hedefler üzerinde çalış
2. Scope dışı hedeflere ASLA istek gönderme
3. Hedef değişikliği için kullanıcı onayı gerekli
4. Üçüncü parti servislere (GitHub, Google vb.) yapılan OSINT sorguları hariç
5. Her yeni hedef için scope doğrulaması yap

## Hedef Kapsamı
- Kullanıcı tarafından verilen IP, domain veya URL'ler scope dahilindedir
- Wildcard scope (*.target.com) belirtilmedikçe subdomain'ler hariçtir
- Internal IP aralıkları (10.x, 172.16-31.x, 192.168.x) sadece lab/CTF ortamlarında geçerlidir

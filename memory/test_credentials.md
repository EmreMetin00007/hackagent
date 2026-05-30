# CCO — Test Credentials

## OpenRouter API Key (tek credential)

| Field | Value |
|-------|-------|
| Provider | OpenRouter (https://openrouter.ai) |
| Key | `sk-or-v1-<YOUR_KEY_HERE>` |
| Key label | `sk-or-v1-97c...c43` |
| Saklama konumu | `/app/.env` (chmod 600) |
| Env variable | `ANTHROPIC_AUTH_TOKEN` (Claude Code için) + `OPENROUTER_API_KEY` (MCP tools için) |
| Bakiye | $23 total, $13.28 kullanılmış (test tarihi itibarıyla) |

### Key kullanımı iki yerde

1. **Claude Code CLI orkestrasyon** (session LLM çağrıları):
   ```
   ANTHROPIC_AUTH_TOKEN → https://openrouter.ai/api/v1/messages
   ```
2. **MCP tool içi çağrılar** (`qwen_analyze`, `generate_exploit_poc`, `parallel_llm_analyze`):
   ```
   OPENROUTER_API_KEY → https://openrouter.ai/api/v1/chat/completions
   ```

### Key alma linki
https://openrouter.ai/keys

## Bu Projede Kullanıcı Auth YOK
CCO bir CLI orkestratördür. Local Kali machine'de çalışır, HTTP API expose etmez,
login/register akışı yoktur. Tek hassas veri OpenRouter API key'idir.

## CTF Platform Token'ları (opsiyonel)
`.env` içinde boş bırakılmış alanlar:
- `CTFD_URL`, `CTFD_TOKEN` — Kendi CTFd instance'ınız için
- `HTB_TOKEN` — HackTheBox API (https://app.hackthebox.com/profile/settings → API Tokens)
- `THM_TOKEN` — TryHackMe API (https://tryhackme.com/settings/account)

Kullanıcı bu platform'ları kullanıyorsa token ekleyebilir; `mcp-ctf-platform`
server bu env'leri okur.

## Faz 0 Test Sonuçları

| Test | Model | Durum | Maliyet |
|------|-------|-------|---------|
| Text yanıt | meta-llama/llama-3.3-70b-instruct | ✅ `OK-HELLO` | $0.12 |
| Text yanıt | qwen/qwen3-next-80b-a3b-instruct | ✅ `OK-HELLO` | $0.12 |
| Text yanıt | qwen/qwen3.6-plus | ⚠️ thinking-only, boş result | - |
| Bash tool use | qwen/qwen3-next-80b-a3b-instruct | ✅ `HELLO-TOOL-USE-WORKS` | $0.24 |
| MCP server discovery | qwen/qwen3-next-80b-a3b-instruct | ✅ 6 server listelendi | $0.43 |
| store_finding MCP tool | qwen/qwen3-next-80b-a3b-instruct | ✅ SQLite'a yazıldı | $0.85 |
| qwen_analyze → OpenRouter | qwen/qwen3.6-plus (tool içi) | ✅ CVE-2021-41773 tespit | $0.86 |

**Toplam harcama (tüm testler):** ~$3.50

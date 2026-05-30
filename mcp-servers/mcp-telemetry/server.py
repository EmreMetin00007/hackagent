#!/usr/bin/env python3
"""
MCP Telemetry Server — HackerAgent Observability & Cost Tracking.
SQLite tabanlı local telemetry: tool çağrıları, LLM maliyetleri, session metrikleri.

Kullanım:
    python server.py
"""

import sqlite3
import os
from datetime import datetime, timedelta
from mcp.server.fastmcp import FastMCP

DB_PATH = os.path.join(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")), "agent_telemetry.db")

mcp = FastMCP(
    "telemetry",
    instructions="HackerAgent Observability — Tool metrikleri, LLM maliyet takibi, session analytics"
)

# ============================================================
# VERİTABANI
# ============================================================

def init_db():
    """Telemetry tablolarını oluştur."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tool çağrı logları
    c.execute('''
        CREATE TABLE IF NOT EXISTS tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            target TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0,
            success INTEGER DEFAULT 1,
            error_message TEXT DEFAULT '',
            token_count INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # LLM API çağrı logları (OpenRouter: Qwen, Hermes)
    c.execute('''
        CREATE TABLE IF NOT EXISTS llm_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT NOT NULL,
            prompt_tokens INTEGER DEFAULT 0,
            completion_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            latency_ms INTEGER DEFAULT 0,
            analysis_type TEXT DEFAULT '',
            success INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Engagement/session logları
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT DEFAULT '',
            target TEXT NOT NULL,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            findings_count INTEGER DEFAULT 0,
            credentials_count INTEGER DEFAULT 0,
            tools_used TEXT DEFAULT '[]',
            status TEXT DEFAULT 'active'
        )
    ''')

    # Savings / optimization events (cost-aware telemetry)
    # event_type: 'compression' | 'cache_hit' | 'planner' | 'reflection' | 'parallel'
    c.execute('''
        CREATE TABLE IF NOT EXISTS savings_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT DEFAULT '{}',
            cost_usd REAL DEFAULT 0,
            saved_tokens INTEGER DEFAULT 0,
            saved_usd REAL DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_savings_session ON savings_events(session_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_savings_type ON savings_events(event_type)")

    conn.commit()
    conn.close()

init_db()

# ============================================================
# COST TABLOSu (model bazlı USD/1M token)
# ============================================================

MODEL_COSTS = {
    "qwen/qwen3.6-plus": {"input": 0.50, "output": 1.50},
    "nousresearch/hermes-4-405b": {"input": 2.00, "output": 6.00},
    "anthropic/claude-sonnet-4": {"input": 3.00, "output": 15.00},
    "anthropic/claude-opus-4": {"input": 15.00, "output": 75.00},
}

def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Model bazlı USD maliyet tahmini."""
    costs = MODEL_COSTS.get(model, {"input": 1.0, "output": 3.0})
    input_cost = (prompt_tokens / 1_000_000) * costs["input"]
    output_cost = (completion_tokens / 1_000_000) * costs["output"]
    return round(input_cost + output_cost, 6)

# ============================================================
# TOOL LOGGING
# ============================================================

@mcp.tool()
def log_tool_call(
    tool_name: str,
    target: str = "",
    duration_ms: int = 0,
    success: bool = True,
    error_message: str = "",
    token_count: int = 0
) -> str:
    """Bir MCP tool çağrısını telemetry'ye kaydet.

    Args:
        tool_name: Çağrılan tool adı (ör: nmap_scan, ffuf_fuzz)
        target: Hedef IP/domain
        duration_ms: Çalışma süresi (milisaniye)
        success: Başarılı mı
        error_message: Hata mesajı (başarısızsa)
        token_count: Üretilen token sayısı (varsa)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO tool_calls (tool_name, target, duration_ms, success, error_message, token_count) VALUES (?, ?, ?, ?, ?, ?)",
            (tool_name, target, duration_ms, 1 if success else 0, error_message, token_count)
        )
        conn.commit()
        conn.close()
        return f"✓ Tool call logged: {tool_name} ({'OK' if success else 'FAIL'}) {duration_ms}ms"
    except Exception as e:
        return f"HATA: Telemetry kaydedilemedi: {e}"


@mcp.tool()
def log_llm_call(
    model: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    latency_ms: int = 0,
    analysis_type: str = "",
    success: bool = True
) -> str:
    """Bir LLM API çağrısını (OpenRouter) telemetry'ye kaydet.

    Args:
        model: Model adı (ör: qwen/qwen3.6-plus, nousresearch/hermes-4-405b)
        prompt_tokens: Giriş token sayısı
        completion_tokens: Çıkış token sayısı
        latency_ms: Yanıt süresi (milisaniye)
        analysis_type: Analiz tipi (vulnerability, traffic, payload vb.)
        success: Başarılı mı
    """
    total = prompt_tokens + completion_tokens
    cost = estimate_cost(model, prompt_tokens, completion_tokens)

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO llm_calls (model, prompt_tokens, completion_tokens, total_tokens, cost_usd, latency_ms, analysis_type, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (model, prompt_tokens, completion_tokens, total, cost, latency_ms, analysis_type, 1 if success else 0)
        )
        conn.commit()
        conn.close()
        return f"✓ LLM call logged: {model} | {total} tokens | ${cost:.4f} | {latency_ms}ms"
    except Exception as e:
        return f"HATA: LLM telemetry kaydedilemedi: {e}"


# ============================================================
# SESSION MANAGEMENT
# ============================================================

@mcp.tool()
def start_session(target: str, session_name: str = "") -> str:
    """Yeni engagement/session başlat.

    Args:
        target: Hedef IP/domain
        session_name: Session açıklaması (opsiyonel)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO sessions (session_name, target, status) VALUES (?, ?, 'active')",
            (session_name or f"Session-{target}", target)
        )
        conn.commit()
        sid = c.lastrowid
        conn.close()
        return f"✓ Session başlatıldı. ID: {sid} | Hedef: {target}"
    except Exception as e:
        return f"HATA: Session başlatılamadı: {e}"


@mcp.tool()
def end_session(session_id: int, findings_count: int = 0, credentials_count: int = 0, tools_used: str = "") -> str:
    """Aktif session'ı sonlandır.

    Args:
        session_id: Session ID
        findings_count: Toplam bulunan zafiyet sayısı
        credentials_count: Toplam bulunan credential sayısı
        tools_used: Kullanılan araçlar (virgülle ayrılmış)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "UPDATE sessions SET end_time=CURRENT_TIMESTAMP, status='completed', findings_count=?, credentials_count=?, tools_used=? WHERE id=?",
            (findings_count, credentials_count, tools_used, session_id)
        )
        conn.commit()
        conn.close()
        return f"✓ Session #{session_id} sonlandırıldı. Bulgular: {findings_count}, Credential: {credentials_count}"
    except Exception as e:
        return f"HATA: Session sonlandırılamadı: {e}"


# ============================================================
# METRİK SORGULARI
# ============================================================

@mcp.tool()
def get_tool_success_rates(period: str = "24h") -> str:
    """Hangi araçlar sık fail ediyor? Başarı oranı ranking'i.

    Args:
        period: Zaman dilimi ('1h', '24h', '7d', '30d', 'all')
    """
    hours = _parse_period(period)
    cutoff = datetime.utcnow() - timedelta(hours=hours) if hours else None

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        query = """
            SELECT tool_name,
                   COUNT(*) as total,
                   SUM(success) as successes,
                   ROUND(AVG(duration_ms), 0) as avg_ms,
                   ROUND(CAST(SUM(success) AS FLOAT) / COUNT(*) * 100, 1) as rate
            FROM tool_calls
        """
        if cutoff:
            query += f" WHERE timestamp >= '{cutoff.isoformat()}'"
        query += " GROUP BY tool_name ORDER BY rate ASC"

        rows = c.execute(query).fetchall()
        conn.close()

        if not rows:
            return f"Son {period} içinde tool çağrısı bulunamadı."

        output = f"📊 Tool Başarı Oranları (son {period}):\n{'='*55}\n"
        output += f"{'Araç':<25} {'Toplam':>6} {'Başarılı':>9} {'Oran':>7} {'Ort.ms':>7}\n"
        output += "-" * 55 + "\n"
        for row in rows:
            emoji = "🔴" if row[4] < 50 else "🟡" if row[4] < 80 else "🟢"
            output += f"{emoji} {row[0]:<23} {row[1]:>6} {row[2]:>9} {row[4]:>6.1f}% {row[3]:>6.0f}\n"

        return output
    except Exception as e:
        return f"HATA: Metrik sorgulanamadı: {e}"


@mcp.tool()
def get_cost_summary(period: str = "7d") -> str:
    """OpenRouter API maliyet özeti (model bazlı).

    Args:
        period: Zaman dilimi ('1h', '24h', '7d', '30d', 'all')
    """
    hours = _parse_period(period)
    cutoff = datetime.utcnow() - timedelta(hours=hours) if hours else None

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        query = """
            SELECT model,
                   COUNT(*) as calls,
                   SUM(prompt_tokens) as total_prompt,
                   SUM(completion_tokens) as total_completion,
                   SUM(total_tokens) as total_tokens,
                   ROUND(SUM(cost_usd), 4) as total_cost,
                   ROUND(AVG(latency_ms), 0) as avg_latency
            FROM llm_calls
        """
        if cutoff:
            query += f" WHERE timestamp >= '{cutoff.isoformat()}'"
        query += " GROUP BY model ORDER BY total_cost DESC"

        rows = c.execute(query).fetchall()
        conn.close()

        if not rows:
            return f"Son {period} içinde LLM çağrısı bulunamadı."

        total_cost = sum(r[5] for r in rows)
        total_tokens_all = sum(r[4] for r in rows)
        total_calls = sum(r[1] for r in rows)

        output = f"💰 LLM Maliyet Özeti (son {period}):\n{'='*65}\n"
        output += f"{'Model':<45} {'Çağrı':>6} {'Token':>8} {'Maliyet':>8}\n"
        output += "-" * 65 + "\n"
        for row in rows:
            output += f"{row[0]:<45} {row[1]:>6} {row[4]:>8} ${row[5]:>7.4f}\n"
        output += "-" * 65 + "\n"
        output += f"{'TOPLAM':<45} {total_calls:>6} {total_tokens_all:>8} ${total_cost:>7.4f}\n"

        return output
    except Exception as e:
        return f"HATA: Maliyet sorgulanamadı: {e}"


@mcp.tool()
def get_metrics_dashboard(period: str = "24h") -> str:
    """Genel telemetry dashboard: tool stats + LLM costs + session info.

    Args:
        period: Zaman dilimi ('1h', '24h', '7d', '30d', 'all')
    """
    hours = _parse_period(period)
    cutoff = datetime.utcnow() - timedelta(hours=hours) if hours else None
    cutoff_clause = f"WHERE timestamp >= '{cutoff.isoformat()}'" if cutoff else ""

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Tool stats
        tool_row = c.execute(f"SELECT COUNT(*), SUM(success), ROUND(AVG(duration_ms),0) FROM tool_calls {cutoff_clause}").fetchone()
        tool_total = tool_row[0] or 0
        tool_success = tool_row[1] or 0
        tool_avg_ms = tool_row[2] or 0

        # LLM stats
        llm_row = c.execute(f"SELECT COUNT(*), SUM(total_tokens), ROUND(SUM(cost_usd),4), ROUND(AVG(latency_ms),0) FROM llm_calls {cutoff_clause}").fetchone()
        llm_total = llm_row[0] or 0
        llm_tokens = llm_row[1] or 0
        llm_cost = llm_row[2] or 0.0
        llm_latency = llm_row[3] or 0

        # Session stats
        sess_row = c.execute("SELECT COUNT(*) FROM sessions WHERE status='active'").fetchone()
        active_sessions = sess_row[0] or 0

        # Top failing tool
        top_fail = c.execute(f"""
            SELECT tool_name, COUNT(*) as fails 
            FROM tool_calls 
            {cutoff_clause} {'AND' if cutoff_clause else 'WHERE'} success=0
            GROUP BY tool_name ORDER BY fails DESC LIMIT 1
        """).fetchone()

        conn.close()

        output = f"""
╔══════════════════════════════════════════════╗
║     📊  HackerAgent Telemetry Dashboard     ║
║              Son {period:>4}                       ║
╚══════════════════════════════════════════════╝

🔧 TOOL ÇAĞRILARI
   Toplam: {tool_total}  |  Başarılı: {tool_success}  |  Başarı: {(tool_success/tool_total*100) if tool_total else 0:.1f}%
   Ort. Süre: {tool_avg_ms:.0f}ms
   En Çok Fail: {top_fail[0] if top_fail else 'Yok'} ({top_fail[1] if top_fail else 0} fail)

🧠 LLM ÇAĞRILARI (OpenRouter)
   Toplam: {llm_total}  |  Token: {llm_tokens:,}
   Maliyet: ${llm_cost:.4f}  |  Ort. Latency: {llm_latency:.0f}ms

📋 SESSION'LAR
   Aktif: {active_sessions}
"""
        return output
    except Exception as e:
        return f"HATA: Dashboard oluşturulamadı: {e}"


# ============================================================
# COST-AWARE SAVINGS EVENTS (Faz-D)
# ============================================================

@mcp.tool()
def log_savings_event(
    session_id: str,
    event_type: str,
    details_json: str = "{}",
    cost_usd: float = 0.0,
    saved_tokens: int = 0,
    saved_usd: float = 0.0,
) -> str:
    """Cost-aware optimization olayını kaydet.

    Compressor, ToolCache, Planner, Reflection gibi mekanizmaların tasarruf
    metriklerini saklar. Session sonunda `get_savings_report` ile raporlanır.

    Args:
        session_id: HackerAgent session ID
        event_type: 'compression' | 'cache_hit' | 'planner' | 'reflection' | 'parallel'
        details_json: JSON string — event-spesifik detaylar
        cost_usd: Bu olayın LLM maliyeti (varsa — compression/planner için)
        saved_tokens: Tahmini tasarruf edilen token sayısı
        saved_usd: Tahmini $ tasarruf
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO savings_events (session_id, event_type, details, cost_usd, saved_tokens, saved_usd) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, event_type, details_json, cost_usd, saved_tokens, saved_usd),
        )
        conn.commit()
        conn.close()
        return f"✓ Savings event logged: {event_type} | cost=${cost_usd:.4f} | saved=${saved_usd:.4f}"
    except Exception as e:
        return f"HATA: Savings event kaydedilemedi: {e}"


@mcp.tool()
def get_savings_report(session_id: str = "") -> str:
    """Bir session (veya tüm) için cost-aware optimization raporunu üret.

    "Bu görev $X maliyetle tamamlandı, %Y token'ı compression kurtardı,
    %Z tool çağrısı cache'den geldi, plan %K doğrulukla izlendi"

    Args:
        session_id: Spesifik session ID; boş bırakılırsa tüm session'lar agrega
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        where = "WHERE session_id = ?" if session_id else ""
        params: tuple = (session_id,) if session_id else ()

        # Event bazlı agrega
        rows = c.execute(
            f"SELECT event_type, COUNT(*), SUM(cost_usd), SUM(saved_tokens), SUM(saved_usd) "
            f"FROM savings_events {where} GROUP BY event_type",
            params,
        ).fetchall()

        # Session genel LLM cost (llm_calls tablosundan)
        # session_id llm_calls tablosunda direkt yok, toplam alıyoruz
        total_llm_cost = 0.0
        total_llm_calls = 0
        if not session_id:
            row = c.execute("SELECT COUNT(*), ROUND(SUM(cost_usd), 4) FROM llm_calls").fetchone()
            total_llm_calls = row[0] or 0
            total_llm_cost = row[1] or 0.0

        conn.close()

        if not rows:
            scope = f"session '{session_id}'" if session_id else "tüm session'lar"
            return f"{scope} için kayıtlı savings event yok.\nHenüz compression/cache/planner tetiklenmedi."

        # Map event_type → aggregates
        by_type: dict[str, dict] = {}
        for r in rows:
            by_type[r[0]] = {
                "count": r[1] or 0,
                "cost_usd": round(r[2] or 0, 4),
                "saved_tokens": r[3] or 0,
                "saved_usd": round(r[4] or 0, 4),
            }

        total_overhead = sum(t["cost_usd"] for t in by_type.values())
        total_saved = sum(t["saved_usd"] for t in by_type.values())
        net_benefit = total_saved - total_overhead

        scope_label = f"Session: {session_id}" if session_id else "Tüm Session'lar"
        output = [
            "╔══════════════════════════════════════════════════════╗",
            "║     💰  Cost-Aware Savings Report                   ║",
            f"║     {scope_label:<47} ║",
            "╚══════════════════════════════════════════════════════╝",
            "",
        ]

        if not session_id and total_llm_calls:
            output.append(f"🧠 Toplam LLM çağrısı: {total_llm_calls}")
            output.append(f"💵 Toplam LLM maliyeti: ${total_llm_cost:.4f}")
            output.append("")

        emoji = {
            "compression": "📦",
            "cache_hit": "♻️",
            "planner": "🗺️",
            "reflection": "🪞",
            "parallel": "⚡",
        }

        for etype, stats in sorted(by_type.items()):
            em = emoji.get(etype, "•")
            output.append(f"{em} {etype.upper()}")
            output.append(f"   Tetiklenme: {stats['count']}")
            if stats["cost_usd"]:
                output.append(f"   Ek maliyet: ${stats['cost_usd']:.4f}")
            if stats["saved_tokens"]:
                output.append(f"   Tasarruf: ~{stats['saved_tokens']:,} token")
            if stats["saved_usd"]:
                output.append(f"   Tasarruf: ~${stats['saved_usd']:.4f}")
            output.append("")

        output.append("─" * 58)
        output.append(f"Optimizasyon overhead'i: ${total_overhead:.4f}")
        output.append(f"Tahmini tasarruf:         ${total_saved:.4f}")
        if net_benefit >= 0:
            output.append(f"✅ NET FAYDA:              ${net_benefit:.4f}")
        else:
            output.append(f"⚠️  NET:                    ${net_benefit:.4f} (overhead > tasarruf)")
        output.append("")

        # Cache hit rate (compression turnaround hesapla)
        cache = by_type.get("cache_hit", {})
        if cache.get("count"):
            output.append(
                f"♻️  Cache hit rate etki: {cache['count']} çağrı MCP'yi bypass etti "
                f"(~{cache.get('saved_tokens', 0):,} token bağlam tasarrufu)"
            )
        comp = by_type.get("compression", {})
        if comp.get("count"):
            saved = comp.get("saved_tokens", 0)
            pct = 100 * saved / max(1, saved + 40000)
            output.append(
                f"📦 Compression etki: {comp['count']} sıkıştırma, "
                f"~{saved:,} token kurtarıldı (~%{pct:.1f} context tasarrufu)"
            )
        pl = by_type.get("planner", {})
        if pl.get("count"):
            output.append(f"🗺️  Plan {pl['count']} kez üretildi (ekstra maliyet: ${pl.get('cost_usd', 0):.4f})")

        return "\n".join(output)
    except Exception as e:
        return f"HATA: Savings report üretilemedi: {e}"

def _parse_period(period: str) -> int:
    """Period string'i saat cinsine çevir. 'all' için 0 döner."""
    if period == "all":
        return 0
    mapping = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720, "90d": 2160}
    return mapping.get(period, 24)


# ============================================================
# SERVER BAŞLAT
# ============================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")

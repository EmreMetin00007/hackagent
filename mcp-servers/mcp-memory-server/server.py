#!/usr/bin/env python3
"""
MCP Memory Server v2.0 — HackerAgent Knowledge Graph Hafızası.
SQLite + NetworkX hibrit: flat tablolar (backward compat) + ilişkisel graph.

Yeni yetenekler:
- Multi-hop reasoning: "Bu SSH key ile S3 bucket'a erişilebilir mi?"
- Attack path planning: Shortest Path to Root
- Exploit chaining: Finding'ler arası zincir ilişkileri
- Credential chain discovery: Credential → Service → Privilege zinciri

Kullanım:
    python server.py
"""

import sqlite3
import os
import json
from mcp.server.fastmcp import FastMCP

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

# Veritabanı dosya yolu (CCO_HOME env var > ~/.cco)
CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
DB_PATH = os.path.join(CCO_HOME, "agent_memory.db")

# Server oluştur
mcp = FastMCP(
    "memory-server",
    instructions="HackerAgent Knowledge Graph Hafızası v2.0 — İlişkisel graph + attack path planning"
)

# ============================================================
# KNOWLEDGE GRAPH ENGINE
# ============================================================

class KnowledgeGraph:
    """NetworkX + SQLite hibrit knowledge graph.

    Graph yapısı:
        (Target)-[HAS_PORT]->(Service)-[RUNS]->(Software)-[VULNERABLE_TO]->(CVE)
                                                           -[EXPLOITABLE_BY]->(Payload)
        (Credential)-[WORKS_ON]->(Service)-[GRANTS]->(Privilege)
        (Finding)-[CHAINS_WITH]->(Finding)
    """

    # Geçerli node tipleri
    NODE_TYPES = ["target", "service", "software", "cve", "credential", "finding", "privilege", "endpoint", "subdomain"]

    # Geçerli ilişki tipleri
    RELATIONSHIP_TYPES = [
        "HAS_PORT", "RUNS", "VULNERABLE_TO", "EXPLOITABLE_BY",
        "WORKS_ON", "GRANTS", "CHAINS_WITH", "CONNECTED_TO",
        "BELONGS_TO", "DISCOVERED_BY", "LEADS_TO", "REQUIRES"
    ]

    # Teknik bazlı varsayılan başarı olasılıkları (Attack Path Planner için)
    TECHNIQUE_SUCCESS_PROBS = {
        "sql_injection": 0.85,
        "sql_injection_blind": 0.65,
        "xss_stored": 0.90,
        "xss_reflected": 0.80,
        "xss_dom": 0.70,
        "rce": 0.95,
        "command_injection": 0.90,
        "ssrf": 0.70,
        "ssrf_blind": 0.50,
        "idor": 0.80,
        "lfi": 0.75,
        "rfi": 0.60,
        "file_upload": 0.65,
        "ssti": 0.75,
        "xxe": 0.70,
        "deserialization": 0.60,
        "buffer_overflow": 0.55,
        "format_string": 0.50,
        "heap_overflow": 0.45,
        "use_after_free": 0.40,
        "race_condition": 0.35,
        "authentication_bypass": 0.70,
        "privilege_escalation": 0.65,
        "default_credentials": 0.90,
        "weak_credentials": 0.80,
        "credential_reuse": 0.75,
        "subdomain_takeover": 0.85,
        "cors_misconfiguration": 0.60,
        "open_redirect": 0.50,
        "csrf": 0.55,
        "jwt_attack": 0.65,
        "path_traversal": 0.70,
    }

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.G = nx.DiGraph() if HAS_NETWORKX else None
        self._init_graph_tables()
        self._load_from_db()

    def _init_graph_tables(self):
        """Graph tablolarını oluştur."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label TEXT DEFAULT '',
                properties TEXT DEFAULT '{}',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                properties TEXT DEFAULT '{}',
                weight REAL DEFAULT 1.0,
                confidence REAL DEFAULT 0.5,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_id) REFERENCES graph_nodes(id),
                FOREIGN KEY (target_id) REFERENCES graph_nodes(id)
            )
        ''')

        # Index'ler
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_edges_rel ON graph_edges(relationship)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type)")

        conn.commit()
        conn.close()

    def _load_from_db(self):
        """SQLite'dan NetworkX graph'a yükle."""
        if not self.G:
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        for row in c.execute("SELECT * FROM graph_nodes"):
            props = json.loads(row["properties"]) if row["properties"] else {}
            self.G.add_node(
                row["id"],
                node_type=row["node_type"],
                label=row["label"],
                **props
            )

        for row in c.execute("SELECT * FROM graph_edges"):
            props = json.loads(row["properties"]) if row["properties"] else {}
            self.G.add_edge(
                row["source_id"],
                row["target_id"],
                relationship=row["relationship"],
                weight=row["weight"],
                confidence=row["confidence"],
                **props
            )

        conn.close()

    def add_node(self, node_id: str, node_type: str, label: str = "", properties: dict = None) -> str:
        """Graph'a düğüm ekle."""
        props = properties or {}
        props_json = json.dumps(props)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO graph_nodes (id, node_type, label, properties) VALUES (?, ?, ?, ?)",
            (node_id, node_type, label or node_id, props_json)
        )
        conn.commit()
        conn.close()

        if self.G:
            self.G.add_node(node_id, node_type=node_type, label=label or node_id, **props)

        return node_id

    def add_edge(self, source_id: str, target_id: str, relationship: str,
                 properties: dict = None, weight: float = 1.0, confidence: float = 0.5) -> int:
        """Graph'a kenar (ilişki) ekle."""
        props = properties or {}
        props_json = json.dumps(props)

        # Node'lar yoksa otomatik oluştur
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT id FROM graph_nodes WHERE id=?", (source_id,))
        if not c.fetchone():
            stype = source_id.split(":")[0] if ":" in source_id else "unknown"
            self.add_node(source_id, stype)

        c.execute("SELECT id FROM graph_nodes WHERE id=?", (target_id,))
        if not c.fetchone():
            ttype = target_id.split(":")[0] if ":" in target_id else "unknown"
            self.add_node(target_id, ttype)

        c.execute(
            "INSERT INTO graph_edges (source_id, target_id, relationship, properties, weight, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            (source_id, target_id, relationship, props_json, weight, confidence)
        )
        conn.commit()
        edge_id = c.lastrowid
        conn.close()

        if self.G:
            self.G.add_edge(source_id, target_id, relationship=relationship,
                            weight=weight, confidence=confidence, **props)

        return edge_id

    def query_neighbors(self, node_id: str, direction: str = "both") -> dict:
        """Bir düğümün komşularını getir."""
        if self.G and node_id in self.G:
            result = {"node": node_id, "outgoing": [], "incoming": []}
            if direction in ("out", "both"):
                for _, target, data in self.G.out_edges(node_id, data=True):
                    result["outgoing"].append({"target": target, **data})
            if direction in ("in", "both"):
                for source, _, data in self.G.in_edges(node_id, data=True):
                    result["incoming"].append({"source": source, **data})
            return result

        # Fallback: SQLite
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        result = {"node": node_id, "outgoing": [], "incoming": []}

        if direction in ("out", "both"):
            for row in c.execute("SELECT * FROM graph_edges WHERE source_id=?", (node_id,)):
                result["outgoing"].append(dict(row))
        if direction in ("in", "both"):
            for row in c.execute("SELECT * FROM graph_edges WHERE target_id=?", (node_id,)):
                result["incoming"].append(dict(row))

        conn.close()
        return result

    def find_shortest_path(self, source: str, target: str) -> list:
        """İki düğüm arası en kısa yol."""
        if not self.G:
            return []
        try:
            return nx.shortest_path(self.G, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def find_all_paths(self, source: str, target: str, max_hops: int = 6) -> list:
        """İki düğüm arası tüm yolları bul (max_hops sınırıyla)."""
        if not self.G:
            return []
        try:
            return list(nx.all_simple_paths(self.G, source, target, cutoff=max_hops))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_attack_paths(self, target_node: str, goal: str = "root") -> list:
        """Target'tan goal'a tüm attack path'leri bul ve skorla."""
        paths = self.find_all_paths(target_node, goal, max_hops=8)

        scored_paths = []
        for path in paths:
            score = self._score_path(path)
            edges_info = []
            for i in range(len(path) - 1):
                edge_data = self.G.get_edge_data(path[i], path[i + 1]) if self.G else {}
                edges_info.append({
                    "from": path[i],
                    "to": path[i + 1],
                    "relationship": edge_data.get("relationship", "?"),
                    "confidence": edge_data.get("confidence", 0.5)
                })
            scored_paths.append({
                "path": path,
                "edges": edges_info,
                "score": score,
                "hops": len(path) - 1
            })

        return sorted(scored_paths, key=lambda x: x["score"], reverse=True)

    def _score_path(self, path: list) -> float:
        """Bir attack path'in başarı olasılığını hesapla.
        P(path) = Π confidence(edge_i) × (1 / hops) complexity_bonus
        """
        if not self.G or len(path) < 2:
            return 0.0

        probability = 1.0
        for i in range(len(path) - 1):
            edge_data = self.G.get_edge_data(path[i], path[i + 1]) or {}
            confidence = edge_data.get("confidence", 0.5)
            probability *= confidence

        # Kısa yolları tercih et (complexity bonus)
        hops = len(path) - 1
        complexity_factor = 1.0 / (1 + 0.1 * hops)

        return round(probability * complexity_factor, 4)

    def find_credential_chains(self, credential_node: str) -> list:
        """Bu credential ile hangi servislere → hangi privilege'lara ulaşılabilir?"""
        if not self.G or credential_node not in self.G:
            return []

        chains = []
        # credential -> (WORKS_ON) -> service -> (GRANTS) -> privilege
        for _, service, edge1 in self.G.out_edges(credential_node, data=True):
            if edge1.get("relationship") == "WORKS_ON":
                for _, privilege, edge2 in self.G.out_edges(service, data=True):
                    if edge2.get("relationship") == "GRANTS":
                        chains.append({
                            "credential": credential_node,
                            "service": service,
                            "privilege": privilege,
                            "confidence": edge1.get("confidence", 0.5) * edge2.get("confidence", 0.5)
                        })
        return chains

    def find_exploit_chains(self, finding_node: str) -> list:
        """Bu finding hangi diğer finding'lerle chain edilebilir?"""
        if not self.G or finding_node not in self.G:
            return []

        chains = []
        # finding -> (CHAINS_WITH) -> finding -> ...
        visited = set()
        stack = [(finding_node, [finding_node])]

        while stack:
            current, path = stack.pop()
            if current in visited and current != finding_node:
                continue
            visited.add(current)

            for _, next_node, data in self.G.out_edges(current, data=True):
                if data.get("relationship") == "CHAINS_WITH" and next_node not in visited:
                    new_path = path + [next_node]
                    chains.append(new_path)
                    stack.append((next_node, new_path))

        return chains

    def get_graph_summary(self, target_filter: str = "") -> dict:
        """Graph'ın genel özetini döndür."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        summary = {
            "total_nodes": 0,
            "total_edges": 0,
            "nodes_by_type": {},
            "edges_by_relationship": {},
            "targets": []
        }

        # Node istatistikleri
        if target_filter:
            rows = c.execute("SELECT node_type, COUNT(*) FROM graph_nodes WHERE id LIKE ? GROUP BY node_type",
                             (f"%{target_filter}%",)).fetchall()
        else:
            rows = c.execute("SELECT node_type, COUNT(*) FROM graph_nodes GROUP BY node_type").fetchall()
        for row in rows:
            summary["nodes_by_type"][row[0]] = row[1]
            summary["total_nodes"] += row[1]

        # Edge istatistikleri
        if target_filter:
            rows = c.execute(
                "SELECT relationship, COUNT(*) FROM graph_edges WHERE source_id LIKE ? OR target_id LIKE ? GROUP BY relationship",
                (f"%{target_filter}%", f"%{target_filter}%")).fetchall()
        else:
            rows = c.execute("SELECT relationship, COUNT(*) FROM graph_edges GROUP BY relationship").fetchall()
        for row in rows:
            summary["edges_by_relationship"][row[0]] = row[1]
            summary["total_edges"] += row[1]

        # Target listesi
        targets = c.execute("SELECT DISTINCT id FROM graph_nodes WHERE node_type='target'").fetchall()
        summary["targets"] = [t[0] for t in targets]

        conn.close()
        return summary

    def suggest_next_action(self, target: str) -> dict:
        """Graph'a bakarak en yüksek başarı olasılıklı sonraki adımı öner."""
        if not self.G:
            return {"suggestion": "NetworkX kurulu değil, graph analizi yapılamıyor."}

        # Target ile ilişkili tüm node'ları bul
        target_nodes = [n for n in self.G.nodes() if target in n]
        if not target_nodes:
            return {"suggestion": f"'{target}' ile ilişkili veri bulunamadı. Önce keşif yapın."}

        suggestions = []

        # Keşfedilmemiş servisler
        for node in target_nodes:
            node_data = self.G.nodes[node]
            out_edges = list(self.G.out_edges(node, data=True))

            if node_data.get("node_type") == "service":
                has_vuln = any(e[2].get("relationship") == "VULNERABLE_TO" for e in out_edges)
                if not has_vuln:
                    suggestions.append({
                        "action": f"Zafiyet taraması yap: {node}",
                        "priority": "high",
                        "reason": "Servis keşfedildi ama zafiyet analizi yapılmadı"
                    })

            if node_data.get("node_type") == "cve":
                has_exploit = any(e[2].get("relationship") == "EXPLOITABLE_BY" for e in out_edges)
                if not has_exploit:
                    suggestions.append({
                        "action": f"Exploit ara: {node}",
                        "priority": "critical",
                        "reason": "CVE bulundu ama exploit henüz yok"
                    })

        # Credential chain fırsatları
        cred_nodes = [n for n in target_nodes if self.G.nodes[n].get("node_type") == "credential"]
        for cred in cred_nodes:
            chains = self.find_credential_chains(cred)
            if not chains:
                suggestions.append({
                    "action": f"Credential test et: {cred} → diğer servislerde dene",
                    "priority": "high",
                    "reason": "Credential bulundu ama başka servislerde denenmedi"
                })

        if not suggestions:
            suggestions.append({
                "action": "Daha fazla keşif yap (port scan, dizin tarama)",
                "priority": "medium",
                "reason": "Mevcut verilerle yeni saldırı vektörü bulunamadı"
            })

        return {
            "target": target,
            "suggestions": sorted(suggestions, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["priority"], 4)),
            "graph_stats": {
                "related_nodes": len(target_nodes),
                "total_graph_nodes": self.G.number_of_nodes(),
                "total_graph_edges": self.G.number_of_edges()
            }
        }


# ============================================================
# VERİTABANI BAŞLATMA
# ============================================================

def init_db():
    """Tüm veritabanı tablolarını oluştur (legacy + graph)."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ---- Legacy tablolar (backward compatibility) ----
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            payload TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url_or_port TEXT NOT NULL,
            protocol TEXT,
            state TEXT,
            technologies TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# Başlangıçta veritabanını hazırla
init_db()

# Knowledge Graph instance
kg = KnowledgeGraph(DB_PATH)

# ============================================================
# LEGACY TOOL'LAR (v1 backward compatibility)
# ============================================================

@mcp.tool()
def store_finding(
    target: str,
    type: str,
    severity: str,
    description: str,
    payload: str = ""
) -> str:
    """Hafızaya yeni bir zafiyet/bulgu (finding) kaydet.
    Otomatik olarak Knowledge Graph'a da eklenir."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO findings (target, type, severity, description, payload) VALUES (?, ?, ?, ?, ?)",
            (target, type, severity, description, payload)
        )
        conn.commit()
        finding_id = c.lastrowid
        conn.close()

        # v2.0: Knowledge Graph'a da ekle
        target_node = f"target:{target}"
        finding_node = f"finding:{type}:{finding_id}"
        kg.add_node(target_node, "target", target)
        kg.add_node(finding_node, "finding", f"{type} ({severity})",
                    {"severity": severity, "description": description[:200], "payload": payload[:200]})
        
        # Confidence: severity'ye göre
        confidence_map = {"critical": 0.95, "high": 0.85, "medium": 0.70, "low": 0.50, "info": 0.30}
        conf = confidence_map.get(severity.lower(), 0.5)
        
        # Success probability: vulnerability type'a göre
        vuln_type_clean = type.lower().replace(" ", "_").replace("-", "_")
        success_prob = kg.TECHNIQUE_SUCCESS_PROBS.get(vuln_type_clean, 0.5)
        
        kg.add_edge(target_node, finding_node, "VULNERABLE_TO", weight=success_prob, confidence=conf)

        return f"Bulgu kaydedildi (ID: {finding_id}) + Knowledge Graph güncellendi ✓"
    except Exception as e:
        return f"HATA: Bulgu kaydedilemedi: {str(e)}"


@mcp.tool()
def store_credential(
    target: str,
    service: str,
    username: str,
    password: str
) -> str:
    """Hafızaya ele geçirilmiş kimlik bilgisi (credential) kaydet.
    Knowledge Graph'ta credential chain otomatik oluşturulur."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO credentials (target, service, username, password) VALUES (?, ?, ?, ?)",
            (target, service, username, password)
        )
        conn.commit()
        cred_id = c.lastrowid
        conn.close()

        # v2.0: Knowledge Graph
        target_node = f"target:{target}"
        service_node = f"service:{target}:{service}"
        cred_node = f"credential:{username}@{service}:{cred_id}"

        kg.add_node(target_node, "target", target)
        kg.add_node(service_node, "service", f"{service} on {target}")
        kg.add_node(cred_node, "credential", f"{username}:***",
                    {"username": username, "service": service})

        kg.add_edge(target_node, service_node, "HAS_PORT", confidence=1.0)
        kg.add_edge(cred_node, service_node, "WORKS_ON", confidence=0.8)

        return f"Credential kaydedildi (ID: {cred_id}) + Knowledge Graph güncellendi ✓"
    except Exception as e:
        return f"HATA: Credential kaydedilemedi: {str(e)}"


@mcp.tool()
def store_endpoint(
    target: str,
    url_or_port: str,
    protocol: str = "http",
    state: str = "open",
    technologies: str = ""
) -> str:
    """Hafızaya yeni keşfedilmiş bir port, servis veya URL endpoint kaydet.
    Knowledge Graph'a otomatik servis/software düğümleri eklenir."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT id FROM endpoints WHERE target=? AND url_or_port=?", (target, url_or_port))
        if c.fetchone():
            conn.close()
            return f"Endpoint ({url_or_port}) zaten hafızada mevcut."

        c.execute(
            "INSERT INTO endpoints (target, url_or_port, protocol, state, technologies) VALUES (?, ?, ?, ?, ?)",
            (target, url_or_port, protocol, state, technologies)
        )
        conn.commit()
        ep_id = c.lastrowid
        conn.close()

        # v2.0: Knowledge Graph
        target_node = f"target:{target}"
        service_node = f"service:{target}:{url_or_port}/{protocol}"

        kg.add_node(target_node, "target", target)
        kg.add_node(service_node, "service", f"{protocol}://{target}:{url_or_port}",
                    {"port": url_or_port, "protocol": protocol, "state": state})

        kg.add_edge(target_node, service_node, "HAS_PORT", confidence=1.0)

        # Teknoloji bilgisi varsa software düğümü ekle
        if technologies:
            for tech in technologies.split(","):
                tech = tech.strip()
                if tech:
                    sw_node = f"software:{tech.lower()}"
                    kg.add_node(sw_node, "software", tech)
                    kg.add_edge(service_node, sw_node, "RUNS", confidence=0.9)

        return f"Endpoint kaydedildi (ID: {ep_id}) + Knowledge Graph güncellendi ✓"
    except Exception as e:
        return f"HATA: Endpoint kaydedilemedi: {str(e)}"


@mcp.tool()
def get_target_memory(target: str) -> str:
    """Belirtilen hedefle ilgili tüm bulguları, credential'ları ve endpoint'leri
    + Knowledge Graph özetini tek bir JSON dökümü olarak getirir."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        result = {"target": target, "findings": [], "credentials": [], "endpoints": []}

        for row in c.execute("SELECT * FROM findings WHERE target LIKE ?", (f"%{target}%",)):
            result["findings"].append(dict(row))

        for row in c.execute("SELECT * FROM credentials WHERE target LIKE ?", (f"%{target}%",)):
            result["credentials"].append(dict(row))

        for row in c.execute("SELECT * FROM endpoints WHERE target LIKE ?", (f"%{target}%",)):
            result["endpoints"].append(dict(row))

        conn.close()

        # v2.0: Graph summary ekle
        graph_summary = kg.get_graph_summary(target)
        result["knowledge_graph"] = graph_summary

        if not any([result["findings"], result["credentials"], result["endpoints"]]) and graph_summary["total_nodes"] == 0:
            return f"Hedef '{target}' için hafızada herhangi bir veri bulunamadı."

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"HATA: Hafıza okunamadı: {str(e)}"


@mcp.tool()
def drop_target_memory(target: str) -> str:
    """Belirtilen hedefle ilgili tüm kayıtları hafızadan tamamen siler (legacy + graph)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Legacy
        c.execute("DELETE FROM findings WHERE target LIKE ?", (f"%{target}%",))
        c.execute("DELETE FROM credentials WHERE target LIKE ?", (f"%{target}%",))
        c.execute("DELETE FROM endpoints WHERE target LIKE ?", (f"%{target}%",))
        # Graph
        c.execute("DELETE FROM graph_edges WHERE source_id LIKE ? OR target_id LIKE ?",
                  (f"%{target}%", f"%{target}%"))
        c.execute("DELETE FROM graph_nodes WHERE id LIKE ?", (f"%{target}%",))
        conn.commit()
        conn.close()

        # NetworkX graph'ı yeniden yükle
        if kg.G:
            nodes_to_remove = [n for n in kg.G.nodes() if target in n]
            kg.G.remove_nodes_from(nodes_to_remove)

        return f"'{target}' ile ilgili tüm hafıza ve graph verisi TEMİZLENDİ."
    except Exception as e:
        return f"HATA: Hafıza silinemedi: {str(e)}"


# ============================================================
# KNOWLEDGE GRAPH TOOL'LARI (v2.0 — Yeni)
# ============================================================

@mcp.tool()
def add_relationship(
    source: str,
    target: str,
    relationship: str,
    properties: str = "",
    weight: float = 1.0,
    confidence: float = 0.5
) -> str:
    """Knowledge Graph'a ilişki (kenar) ekle.

    Node ID formatı: "tip:değer" (ör: "target:10.10.10.5", "service:ssh:22", "cve:CVE-2024-1234")

    Args:
        source: Kaynak düğüm ID'si
        target: Hedef düğüm ID'si
        relationship: İlişki tipi (HAS_PORT, RUNS, VULNERABLE_TO, EXPLOITABLE_BY,
                      WORKS_ON, GRANTS, CHAINS_WITH, CONNECTED_TO, LEADS_TO, REQUIRES)
        properties: JSON formatında ek özellikler (opsiyonel)
        weight: Kenar ağırlığı (0.0-1.0, saldırı path scoring için)
        confidence: Güven skoru (0.0-1.0)
    """
    try:
        props = json.loads(properties) if properties else {}
    except json.JSONDecodeError:
        props = {"raw": properties}

    edge_id = kg.add_edge(source, target, relationship, props, weight, confidence)
    return f"İlişki eklendi (ID: {edge_id}): {source} -[{relationship}]-> {target} (conf: {confidence})"


@mcp.tool()
def query_attack_paths(
    from_node: str,
    to_node: str = "root",
    max_hops: int = 6
) -> str:
    """Knowledge Graph'ta iki düğüm arasındaki tüm saldırı yollarını bul ve skorla.
    Attack Path Planner: Her yol başarı olasılığına göre sıralanır.

    Args:
        from_node: Başlangıç düğümü (ör: "target:10.10.10.5")
        to_node: Hedef düğüm (ör: "root", "privilege:admin")
        max_hops: Maksimum adım sayısı
    """
    if not HAS_NETWORKX:
        return "HATA: NetworkX kurulu değil. pip install networkx"

    paths = kg.get_attack_paths(from_node, to_node)

    if not paths:
        # Tüm 'privilege' veya 'root' düğümlerini dene
        all_paths = []
        if kg.G:
            goal_nodes = [n for n in kg.G.nodes() if "root" in n.lower() or "admin" in n.lower()
                          or kg.G.nodes[n].get("node_type") == "privilege"]
            for goal in goal_nodes:
                gp = kg.get_attack_paths(from_node, goal)
                all_paths.extend(gp)

        if not all_paths:
            return f"'{from_node}' → '{to_node}' arasında saldırı yolu bulunamadı.\nGraph'a daha fazla veri ekleyin (store_finding, store_endpoint, add_relationship)."
        paths = sorted(all_paths, key=lambda x: x["score"], reverse=True)

    output = f"🗡️ Attack Paths: {from_node} → {to_node}\n{'='*60}\n"
    for i, p in enumerate(paths[:10], 1):
        output += f"\n#{i} [Skor: {p['score']:.4f}] ({p['hops']} adım)\n"
        output += f"  Yol: {' → '.join(p['path'])}\n"
        for edge in p["edges"]:
            output += f"    {edge['from']} -[{edge['relationship']}]→ {edge['to']} (güven: {edge['confidence']:.2f})\n"

    return output


@mcp.tool()
def find_exploitable_chains(target: str) -> str:
    """Bir hedef için credential chain'leri ve exploit chain'lerini bul.
    Multi-hop reasoning: 'Bu SSH key ile S3 bucket'a erişilebilir mi?'

    Args:
        target: Hedef IP/domain
    """
    if not HAS_NETWORKX:
        return "HATA: NetworkX kurulu değil."

    output = f"🔗 Exploit Chain Analizi: {target}\n{'='*60}\n"

    # Credential chains
    cred_nodes = [n for n in (kg.G.nodes() if kg.G else [])
                  if "credential" in n and target in n]
    if cred_nodes:
        output += f"\n📋 Credential Chain'ler ({len(cred_nodes)} credential):\n"
        for cred in cred_nodes:
            chains = kg.find_credential_chains(cred)
            if chains:
                for chain in chains:
                    output += f"  🔑 {chain['credential']} → {chain['service']} → {chain['privilege']} (güven: {chain['confidence']:.2f})\n"
            else:
                output += f"  🔑 {cred} → (chain bulunamadı — diğer servislerde deneyin)\n"
    else:
        output += "\n📋 Credential bulunamadı.\n"

    # Finding exploit chains
    finding_nodes = [n for n in (kg.G.nodes() if kg.G else [])
                     if "finding" in n]
    target_findings = [n for n in finding_nodes
                       if any(target in pred for pred in (kg.G.predecessors(n) if kg.G else []))]
    if target_findings:
        output += f"\n⚡ Exploit Chain'ler ({len(target_findings)} finding):\n"
        for finding in target_findings:
            chains = kg.find_exploit_chains(finding)
            if chains:
                for chain in chains:
                    output += f"  💥 {' → '.join(chain)}\n"
            else:
                output += f"  💥 {finding} → (zincir bulunamadı)\n"
    else:
        output += "\n⚡ Finding bulunamadı.\n"

    return output


@mcp.tool()
def get_knowledge_graph_summary(target: str = "") -> str:
    """Knowledge Graph'ın genel özetini döndür.

    Args:
        target: Filtre (opsiyonel — boş bırakılırsa tüm graph)
    """
    summary = kg.get_graph_summary(target)

    output = f"📊 Knowledge Graph Özeti{f' ({target})' if target else ''}\n{'='*50}\n"
    output += f"Toplam düğüm: {summary['total_nodes']}\n"
    output += f"Toplam ilişki: {summary['total_edges']}\n"

    if summary["nodes_by_type"]:
        output += "\nDüğüm Tipleri:\n"
        for ntype, count in sorted(summary["nodes_by_type"].items()):
            emoji = {"target": "🎯", "service": "⚙️", "software": "📦", "cve": "🐛",
                     "credential": "🔑", "finding": "💥", "privilege": "👑", "endpoint": "🌐"}.get(ntype, "📍")
            output += f"  {emoji} {ntype}: {count}\n"

    if summary["edges_by_relationship"]:
        output += "\nİlişki Tipleri:\n"
        for rel, count in sorted(summary["edges_by_relationship"].items()):
            output += f"  → {rel}: {count}\n"

    if summary["targets"]:
        output += "\nKayıtlı Hedefler:\n"
        for t in summary["targets"]:
            output += f"  🎯 {t}\n"

    return output


@mcp.tool()
def suggest_next_action(target: str) -> str:
    """Knowledge Graph'a bakarak hedef için en yüksek öncelikli sonraki adımı öner.
    Graph'taki boşlukları tespit eder ve akıllı öneriler sunar.

    Args:
        target: Hedef IP/domain
    """
    if not HAS_NETWORKX:
        return "HATA: NetworkX kurulu değil."

    result = kg.suggest_next_action(target)

    output = f"🧠 Akıllı Öneri: {target}\n{'='*50}\n"
    output += f"İlişkili düğüm: {result.get('graph_stats', {}).get('related_nodes', 0)}\n\n"

    if "suggestion" in result:
        output += f"💡 {result['suggestion']}\n"
    elif "suggestions" in result:
        for i, s in enumerate(result["suggestions"][:5], 1):
            priority_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(s["priority"], "⚪")
            output += f"{priority_emoji} #{i} [{s['priority'].upper()}] {s['action']}\n"
            output += f"   Gerekçe: {s['reason']}\n\n"

    return output


# ============================================================
# SERVER BAŞLAT
# ============================================================

if __name__ == "__main__":
    mcp.run()

#!/usr/bin/env python3
"""
Attack Path Planner — Bayesian Attack Graph + Shortest Path to Root.

Bu script, Knowledge Graph verileri üzerine kurulu bir saldırı planlayıcıdır.
Memory server'ın graph engine'ini kullanarak:
- Her finding'e success probability atar
- Attack path'leri otomatik ranking ile sıralar
- Shortest Path to Root algoritması uygular

Kullanım (standalone test):
    python attack_planner.py --target 10.10.10.5
    python attack_planner.py --target example.com --goal privilege:admin
"""

import sys
import os
import json
import sqlite3

# Proje kökünü bul
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(PROJECT_DIR, "mcp-servers", "mcp-memory-server"))

try:
    import networkx as nx
except ImportError:
    print("HATA: networkx gerekli. pip install networkx")
    sys.exit(1)


class AttackPathPlanner:
    """Bayesian attack path planning engine.

    Memory server'ın KnowledgeGraph sınıfıyla entegre çalışır.
    Standalone olarak da kullanılabilir.
    """

    # Saldırı tekniklerinin varsayılan başarı olasılıkları
    TECHNIQUE_PROBS = {
        # Web
        "sql_injection": 0.85,
        "xss_stored": 0.90,
        "xss_reflected": 0.80,
        "rce": 0.95,
        "command_injection": 0.90,
        "ssrf": 0.70,
        "idor": 0.80,
        "lfi": 0.75,
        "rfi": 0.60,
        "file_upload": 0.65,
        "ssti": 0.75,
        "xxe": 0.70,
        "deserialization": 0.60,
        "path_traversal": 0.70,
        "authentication_bypass": 0.70,
        # Binary
        "buffer_overflow": 0.55,
        "format_string": 0.50,
        "heap_overflow": 0.45,
        "use_after_free": 0.40,
        "rop_chain": 0.50,
        "ret2libc": 0.55,
        # Network
        "default_credentials": 0.90,
        "weak_credentials": 0.80,
        "credential_reuse": 0.75,
        "privilege_escalation": 0.65,
        "lateral_movement": 0.60,
        "kerberoast": 0.70,
        "pass_the_hash": 0.75,
        "smb_relay": 0.65,
    }

    # Complexity multipliers (düşük = daha zor)
    COMPLEXITY_FACTORS = {
        "trivial": 1.0,     # Otomatize edilebilir (default creds, known exploit)
        "easy": 0.85,       # Basit exploit geliştirme
        "medium": 0.65,     # Özelleştirme gerekiyor
        "hard": 0.45,       # Araştırma + özel exploit
        "extreme": 0.25,    # 0-day düzeyinde
    }

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(
            os.environ.get("HACKERAGENT_HOME", os.path.expanduser("~/.hackeragent")),
            "agent_memory.db",
        )
        self.G = nx.DiGraph()
        self._load_graph()

    def _load_graph(self):
        """SQLite'dan graph'ı yükle."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        try:
            for row in c.execute("SELECT * FROM graph_nodes"):
                props = json.loads(row["properties"]) if row["properties"] else {}
                self.G.add_node(row["id"], node_type=row["node_type"], label=row["label"], **props)

            for row in c.execute("SELECT * FROM graph_edges"):
                props = json.loads(row["properties"]) if row["properties"] else {}
                self.G.add_edge(row["source_id"], row["target_id"],
                                relationship=row["relationship"],
                                weight=row["weight"],
                                confidence=row["confidence"], **props)
        except sqlite3.OperationalError:
            pass  # Tablolar henüz yok

        conn.close()

    def score_path(self, path: list) -> float:
        """Bir attack path'in toplam başarı olasılığını hesapla.

        P(path) = Π P(step_i) × complexity_factor × (1 / (1 + 0.1*hops))
        """
        if len(path) < 2:
            return 0.0

        probability = 1.0
        for i in range(len(path) - 1):
            edge_data = self.G.get_edge_data(path[i], path[i + 1]) or {}
            confidence = edge_data.get("confidence", 0.5)
            weight = edge_data.get("weight", 0.5)
            probability *= (confidence * 0.6 + weight * 0.4)  # Ağırlıklı ortalama

        # Hop penalty: Kısa yolları tercih et
        hops = len(path) - 1
        hop_penalty = 1.0 / (1.0 + 0.15 * hops)

        return round(probability * hop_penalty, 6)

    def rank_all_paths(self, source: str, goals: list = None, max_hops: int = 8) -> list:
        """Tüm path'leri score'a göre sırala."""
        if goals is None:
            goals = [n for n in self.G.nodes()
                     if any(kw in n.lower() for kw in ["root", "admin", "privilege", "flag"])]

        all_paths = []
        for goal in goals:
            try:
                paths = list(nx.all_simple_paths(self.G, source, goal, cutoff=max_hops))
                for path in paths:
                    score = self.score_path(path)
                    all_paths.append({
                        "path": path,
                        "score": score,
                        "hops": len(path) - 1,
                        "goal": goal,
                        "edges": self._get_edge_details(path)
                    })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return sorted(all_paths, key=lambda x: x["score"], reverse=True)

    def suggest_optimal_strategy(self, target: str) -> dict:
        """Hedef için optimal saldırı stratejisini öner."""
        target_nodes = [n for n in self.G.nodes() if target in n]
        if not target_nodes:
            return {
                "strategy": "reconnaissance",
                "reason": f"'{target}' için graph'ta veri yok. Önce keşif yapın.",
                "recommended_tools": ["nmap", "ffuf", "subfinder", "whatweb"]
            }

        # Ana target node'u bul
        source = next((n for n in target_nodes if self.G.nodes[n].get("node_type") == "target"), target_nodes[0])

        ranked = self.rank_all_paths(source)

        if not ranked:
            # Explorable paths yok — daha fazla keşif gerekli
            unexplored = self._find_unexplored_services(target)
            return {
                "strategy": "deepening_recon",
                "reason": "Attack path bulunamadı. Mevcut servisleri daha derinlemesine inceleyin.",
                "unexplored_services": unexplored,
                "recommended_tools": ["nuclei", "nikto", "sqlmap"]
            }

        best = ranked[0]
        return {
            "strategy": "exploit",
            "best_path": best,
            "total_paths": len(ranked),
            "confidence": best["score"],
            "recommended_sequence": self._path_to_commands(best)
        }

    def _get_edge_details(self, path: list) -> list:
        """Path'teki her edge'in detaylarını getir."""
        details = []
        for i in range(len(path) - 1):
            data = self.G.get_edge_data(path[i], path[i + 1]) or {}
            details.append({
                "from": path[i],
                "to": path[i + 1],
                "relationship": data.get("relationship", "?"),
                "confidence": data.get("confidence", 0.5),
                "weight": data.get("weight", 0.5)
            })
        return details

    def _find_unexplored_services(self, target: str) -> list:
        """Zafiyet taraması yapılmamış servisleri bul."""
        unexplored = []
        for node in self.G.nodes():
            if target in node and self.G.nodes[node].get("node_type") == "service":
                has_vuln = any(
                    self.G.get_edge_data(node, succ, {}).get("relationship") == "VULNERABLE_TO"
                    for succ in self.G.successors(node)
                )
                if not has_vuln:
                    unexplored.append(node)
        return unexplored

    def _path_to_commands(self, path_info: dict) -> list:
        """Attack path'i aksiyona dönüştür."""
        commands = []
        for edge in path_info.get("edges", []):
            rel = edge["relationship"]
            target_node = edge["to"]

            if rel == "VULNERABLE_TO":
                commands.append(f"Zafiyet doğrula: {target_node}")
            elif rel == "EXPLOITABLE_BY":
                commands.append(f"Exploit çalıştır: {target_node}")
            elif rel == "WORKS_ON":
                commands.append(f"Credential dene: {edge['from']} → {target_node}")
            elif rel == "GRANTS":
                commands.append(f"Yetki kazan: {target_node}")
            elif rel == "LEADS_TO":
                commands.append(f"İlerle: {edge['from']} → {target_node}")
            else:
                commands.append(f"{rel}: {edge['from']} → {target_node}")

        return commands

    def update_probability(self, technique: str, success: bool):
        """Gerçek sonuçlarla olasılıkları güncelle (Bayesian update)."""
        current = self.TECHNIQUE_PROBS.get(technique, 0.5)
        # Basit Bayesian update: prior * likelihood
        if success:
            updated = current + (1 - current) * 0.1  # Başarı → olasılık artar
        else:
            updated = current * 0.9  # Başarısızlık → olasılık azalır

        self.TECHNIQUE_PROBS[technique] = round(min(max(updated, 0.05), 0.99), 4)
        return self.TECHNIQUE_PROBS[technique]

    def generate_report(self, target: str) -> str:
        """Hedef için kapsamlı attack path raporu oluştur."""
        target_nodes = [n for n in self.G.nodes() if target in n]

        report = f"""
╔══════════════════════════════════════════════╗
║     🗡️  Attack Path Analysis Report          ║
║     Target: {target:<32} ║
╚══════════════════════════════════════════════╝

📊 Graph İstatistikleri:
  Toplam düğüm: {self.G.number_of_nodes()}
  Toplam kenar: {self.G.number_of_edges()}
  Hedefle ilişkili: {len(target_nodes)}
"""

        strategy = self.suggest_optimal_strategy(target)
        report += f"\n🎯 Önerilen Strateji: {strategy['strategy'].upper()}\n"
        report += f"  Gerekçe: {strategy.get('reason', 'N/A')}\n"

        if "best_path" in strategy:
            bp = strategy["best_path"]
            report += f"\n  En İyi Yol (Skor: {bp['score']:.4f}, {bp['hops']} adım):\n"
            report += f"  {'→'.join(bp['path'])}\n"

            if "recommended_sequence" in strategy:
                report += "\n  📝 Adım Adım Plan:\n"
                for i, cmd in enumerate(strategy["recommended_sequence"], 1):
                    report += f"    {i}. {cmd}\n"

        return report


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HackerAgent Attack Path Planner")
    parser.add_argument("--target", required=True, help="Hedef IP/domain")
    parser.add_argument("--goal", default=None, help="Hedef düğüm (ör: privilege:admin)")
    parser.add_argument("--db", default=None, help="Veritabanı yolu")
    parser.add_argument("--max-hops", type=int, default=8, help="Maksimum hop sayısı")

    args = parser.parse_args()

    planner = AttackPathPlanner(args.db)
    print(planner.generate_report(args.target))

#!/usr/bin/env python3
"""
Swarm Orchestrator — Multi-Agent Swarm Yönetimi.
Her agent kendi context window'una sahip; orkestratörün context'i kirlenmez.

Roller:
  - Recon Agent (Qwen tabanlı, ucuz)
  - Exploit Agent (Hermes tabanlı, PoC üretici)
  - Validate Agent (Qwen, dikkatli)
  - Report Agent (Qwen, formatting)

Kullanım:
    MCP tool olarak: swarm_dispatch, swarm_status
    Standalone: python swarm_orchestrator.py --task "..." --roles recon,exploit
"""

import os
import json
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class AgentRole(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REPORT = "report"


# Model mapping — tüm roller için OpenRouter üzerinden Qwen/Hermes (Claude bağımsız)
ROLE_MODELS = {
    AgentRole.RECON: "qwen/qwen3.6-plus",
    AgentRole.EXPLOIT: "nousresearch/hermes-4-405b",
    AgentRole.VALIDATE: "qwen/qwen3.6-plus",
    AgentRole.REPORT: "qwen/qwen3.6-plus",
}

# Role-specific system prompts
ROLE_PROMPTS = {
    AgentRole.RECON: """You are an expert reconnaissance agent. Your job is to:
- Enumerate targets (subdomains, ports, services, technologies)
- Identify attack surface and potential entry points
- Map the target's infrastructure
- Report findings in structured JSON format
Be thorough but efficient. Focus on actionable intelligence.""",

    AgentRole.EXPLOIT: """You are an expert exploit development and security validation agent. Your job is to:
- Generate working proof-of-concept payloads for identified vulnerabilities
- Create PoC code for verification in controlled test environments
- Suggest bypass techniques for WAFs and security controls
- Output exact commands and payloads ready for authorized testing
Focus on technical precision and reproducibility.""",

    AgentRole.VALIDATE: """You are a careful security validation agent. Your job is to:
- Verify that exploits work as intended
- Assess the real impact of vulnerabilities
- Check for false positives
- Ensure findings are reproducible
- Rate severity accurately (CVSS)
Be thorough and conservative in your assessments.""",

    AgentRole.REPORT: """You are a professional security report writer. Your job is to:
- Create clear, professional vulnerability reports
- Include executive summary, technical details, and remediation
- Format for HackerOne/Bugcrowd submission standards
- Calculate CVSS scores accurately
- Include PoC steps that are easy to reproduce
Output in markdown format.""",
}


@dataclass
class AgentTask:
    """Bir agent'a verilen görev."""
    task_id: str
    role: AgentRole
    prompt: str
    context: dict = field(default_factory=dict)
    status: str = "pending"  # pending, running, completed, failed
    result: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    tokens_used: int = 0
    cost_usd: float = 0.0


class SwarmOrchestrator:
    """Lightweight multi-agent swarm orchestrator."""

    def __init__(self):
        self.tasks: dict[str, AgentTask] = {}
        self.api_key = self._get_api_key()
        self.task_counter = 0

    def _get_api_key(self) -> str:
        """API key'i al (env > config.yaml > legacy settings.json)."""
        key = os.environ.get("OPENROUTER_API_KEY", "")
        if key:
            return key

        home = os.environ.get("HACKERAGENT_HOME", os.path.expanduser("~/.hackeragent"))
        candidates = [
            os.path.join(home, "config.yaml"),
            os.path.join(home, "settings.json"),
            os.path.expanduser("~/.claude/settings.json"),  # legacy
        ]
        for path in candidates:
            try:
                if not os.path.exists(path):
                    continue
                if path.endswith((".yaml", ".yml")):
                    try:
                        import yaml
                        with open(path, "r") as f:
                            data = yaml.safe_load(f) or {}
                        k = (
                            data.get("llm", {}).get("openrouter_api_key")
                            or data.get("openrouter_api_key", "")
                        )
                        if k:
                            return k
                    except ImportError:
                        continue
                else:
                    with open(path, "r") as f:
                        k = json.load(f).get("openrouter_api_key", "")
                        if k:
                            return k
            except Exception:
                continue
        return ""

    def create_task(self, role: AgentRole, prompt: str, context: dict = None) -> str:
        """Yeni agent görevi oluştur."""
        self.task_counter += 1
        task_id = f"swarm-{role.value}-{self.task_counter}"
        task = AgentTask(
            task_id=task_id,
            role=role,
            prompt=prompt,
            context=context or {}
        )
        self.tasks[task_id] = task
        return task_id

    def execute_task(self, task_id: str) -> str:
        """Tek bir agent görevini çalıştır."""
        task = self.tasks.get(task_id)
        if not task:
            return f"HATA: Görev bulunamadı: {task_id}"

        if not self.api_key:
            return "HATA: OpenRouter API key bulunamadı."

        task.status = "running"
        task.started_at = datetime.utcnow().isoformat()

        model = ROLE_MODELS.get(task.role, "qwen/qwen3.6-plus")
        system_prompt = ROLE_PROMPTS.get(task.role, "")

        # Context'i prompt'a ekle
        full_prompt = task.prompt
        if task.context:
            full_prompt = f"Context:\n{json.dumps(task.context, indent=2)}\n\nTask:\n{task.prompt}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://hackeragent.local",
            "X-Title": f"HackerAgent Swarm ({task.role.value})"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_prompt}
            ],
            "max_tokens": 4096,
        }

        try:
            resp = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers, json=payload, timeout=120
            )
            resp.raise_for_status()
            result = resp.json()

            task.result = result['choices'][0]['message']['content']
            task.status = "completed"
            task.tokens_used = result.get('usage', {}).get('total_tokens', 0)
            task.completed_at = datetime.utcnow().isoformat()

            return task.result
        except Exception as e:
            task.status = "failed"
            task.result = f"HATA: {e}"
            task.completed_at = datetime.utcnow().isoformat()
            return task.result

    def dispatch_parallel(self, tasks: list[tuple[AgentRole, str, dict]]) -> dict:
        """Birden fazla agent'ı paralel çalıştır.

        Args:
            tasks: [(role, prompt, context), ...] listesi
        """
        task_ids = []
        for role, prompt, context in tasks:
            tid = self.create_task(role, prompt, context)
            task_ids.append(tid)

        # Paralel execution
        results = {}
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(task_ids)) as executor:
            futures = {executor.submit(self.execute_task, tid): tid for tid in task_ids}
            for future in concurrent.futures.as_completed(futures):
                tid = futures[future]
                try:
                    results[tid] = future.result()
                except Exception as e:
                    results[tid] = f"HATA: {e}"

        return results

    def handoff(self, from_task_id: str, to_role: AgentRole, additional_prompt: str = "") -> str:
        """Agent'lar arası context handoff.
        Bir agent'ın sonucunu diğerine input olarak ver.
        """
        from_task = self.tasks.get(from_task_id)
        if not from_task:
            return f"HATA: Kaynak görev bulunamadı: {from_task_id}"

        if from_task.status != "completed":
            return f"HATA: Kaynak görev henüz tamamlanmadı: {from_task.status}"

        handoff_prompt = additional_prompt or f"Previous agent ({from_task.role.value}) output'unu analiz et ve görevini yap."
        context = {
            "previous_agent": from_task.role.value,
            "previous_output": from_task.result[:3000],
            "original_task": from_task.prompt[:500]
        }

        new_task_id = self.create_task(to_role, handoff_prompt, context)
        return self.execute_task(new_task_id)

    def get_status(self) -> dict:
        """Tüm görevlerin durumu."""
        summary = {
            "total": len(self.tasks),
            "pending": 0, "running": 0, "completed": 0, "failed": 0,
            "tasks": []
        }
        for tid, task in self.tasks.items():
            summary[task.status] = summary.get(task.status, 0) + 1
            summary["tasks"].append({
                "id": tid,
                "role": task.role.value,
                "status": task.status,
                "tokens": task.tokens_used,
                "result_preview": task.result[:100] + "..." if len(task.result) > 100 else task.result
            })
        return summary


# Global orchestrator instance
_orchestrator = None

def get_orchestrator() -> SwarmOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SwarmOrchestrator()
    return _orchestrator


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HackerAgent Swarm Orchestrator")
    parser.add_argument("--task", required=True, help="Görev açıklaması")
    parser.add_argument("--roles", default="recon", help="Agent rolleri (virgülle ayrılmış)")
    parser.add_argument("--target", default="", help="Hedef bilgisi")

    args = parser.parse_args()

    orch = SwarmOrchestrator()
    roles = [AgentRole(r.strip()) for r in args.roles.split(",")]

    if len(roles) == 1:
        tid = orch.create_task(roles[0], args.task, {"target": args.target})
        print(orch.execute_task(tid))
    else:
        tasks = [(role, args.task, {"target": args.target}) for role in roles]
        results = orch.dispatch_parallel(tasks)
        for tid, result in results.items():
            print(f"\n{'='*50}\n[{tid}]\n{'='*50}\n{result}")

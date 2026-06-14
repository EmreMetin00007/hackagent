---
name: deep-reasoning
description: "CCO'nun güçlü 'beyin' katmanı (biliş motoru). Kompleks, belirsiz veya yüksek-değerli görevlerde DERİN DÜŞÜNME yapar: ilgili geçmiş dersleri hatırlar (kalıcı öğrenme), Bayesçi beklenen-değer ile saldırı planı kurar (tree-of-thought) ve seçilen yolu Reflexion (actor→critic→validator→retry) ile kendini-düzelterek sağlamlaştırır. Ayrıca: Kill-Chain Intelligence (compose_attack_chains — bulguları SSRF→IMDS→RCE gibi çok-adımlı zincirlere bağlar; büyük ödül = zincir), WAF-aware Payload Evolution (evolve_payload — bloklanınca payload evrimleştirir) ve Exploitability Score (kalibre güven, false-positive guard). Bu skill'i şu durumlarda kullan: yeni bir hedefe/engagement'a başlarken; 'nereden başlamalıyım', 'en yüksek impact ne', 'sonraki adım', 'plan', 'strateji', 'zincirle', 'chain', 'düşün', 'analiz et' dendiğinde; bir exploit/PoC üretmeden önce kendini eleştirmek istediğinde; bir payload WAF'a takılınca; bir bulgunun gerçek sömürülebilirliğini skorlarken; bir vektör başarısız olup strateji değiştirmen gerektiğinde. Tek kapı: deep_think. Tool sonrası daima validator ile doğrula ve record_lesson ile öğren."
---

# 🧠 Derin Düşünme (Reasoning / Beyin Katmanı)

> CCO'nun zekası tek bir session modelinden ibaret değildir. `mcp-reasoning`
> server'ı üç piları birleştirir: **kalıcı öğrenme** + **Bayesçi planlama** +
> **Reflexion (kendini düzeltme)**. Karmaşık görevde **körlemesine tool çalıştırma —
> önce `deep_think`**.

## Tek kapı: `deep_think`

```
mcp__reasoning__deep_think(task, target, scope, context)
  → step 1: recall_lessons   (geçmişte ne işe yaradı?)
  → step 2: plan_attack_tree (en yüksek EV saldırı yolu — graph + Bayes)
  → step 3: chosen_action    (validator hook + önerilen tool ile)
  → step 4: reason_reflexion (actor↔critic, self-correct)
  → next_steps: DOĞRULA → EXPLOIT → record_lesson
```

## Üç Pilar

### 1a — Reflexion (kendini düzelten akıl yürütme)
```
mcp__reasoning__reason_reflexion(task, target, context, artifact_kind, max_iters)
  actor (CCO_REASON_MODEL) üretir → critic (CCO_CRITIC_MODEL) eleştirir →
  actor revize eder → critic onaylayana kadar. Halüsinasyonu düşürür.
mcp__reasoning__critic_review(artifact, kind, context)   # tek geçişli eleştiri
```
> Actor ≠ Critic (farklı modeller) → daha sert, daha yararlı eleştiri.
> Onaylansa bile **mcp__validator ile deterministik doğrula**.

### 1d — Bayesçi saldırı planlama (tree-of-thought + EV)
```
mcp__reasoning__plan_attack_tree(target, scope, expand)   # sıralı vektörler + ToT zinciri
mcp__reasoning__next_best_action(target)                  # tek en yüksek-EV aksiyon (hızlı)
```
> `EV = blended_prob × impact × (1 − 0.4·effort)`. memory'deki bulgu/endpoint'leri
> okur; her vektörü `validate_with` (validator) ve `recommended_tool` ile döndürür.

### 1e — Kalıcı öğrenme (zamanla akıllanır)
```
mcp__reasoning__record_lesson(context, technique, action, outcome, worked, target_tech, tags)
mcp__reasoning__recall_lessons(context, technique, tags, k)
mcp__reasoning__lesson_stats()
```
> **Her exploit denemesinden sonra** record_lesson çağır (BAŞARI ve BAŞARISIZLIK).
> Öğrenilen win-rate'ler `plan_attack_tree`'nin Bayesçi önceliklerine **otomatik
> karışır** → planlayıcı zamanla bu ajanın gerçek deneyimine göre kalibre olur.

## Altın Döngü (beynin akıllanması)

```
deep_think → validate (deterministik) → exploit → record_lesson(worked=?)
     ▲                                                          │
     └──────────── öğrenilen win-rate priors'ı günceller ◄──────┘
```

## ⚡ Zeka Katmanı v2 — piyasa farklılaştırıcıları

### (a) Kill-Chain Intelligence — bulguları zincirle (büyük ödül = zincir)
```
mcp__reasoning__compose_attack_chains(target, scope, max_depth, top_n)
   → memory'deki bulguları deterministik ÇOK-ADIMLI kill-chain'lere bağlar:
     SSRF→IMDS→IAM→bulut ele geçirme · LFI→log poisoning→RCE ·
     open-redirect→OAuth token→ATO · IDOR→ATO · file_upload→webshell→RCE
   → her zinciri EV (bileşik olasılık × yükseltilmiş impact × effort) ile sıralar
mcp__reasoning__kill_chain_report(chain_json)   → reprodüklenebilir Markdown trace
```
> Tek tek orta-seviye bulgular ZİNCİRLENEREK kritik etkiye yükselir. Recon/exploit
> sonrası `compose_attack_chains` çağır; en yüksek-EV zinciri adım adım yürü, her
> adımı validator ile CONFIRMED yap. **Bu, büyük bounty'leri kazandıran düşünme.**

### (d) WAF-aware Payload Evolution — bloklanınca evrimleş
```
mcp__reasoning__evolve_payload(payload, technique, blocked_by, generations, population)
   → WAF/filtre bloğuna göre payload'ı guided mutasyonla evrimleştirir
     (inline_comment, keyword_split, ${IFS}, tag-breakup, unicode_slash, b64_wrap...)
mcp__reasoning__record_payload_result(technique, operators, worked, blocked_by)
   → hangi operatör işe yaradı? öğrenir → sonraki evrimi yönlendirir (zamanla bypass↑)
```
> Bir payload bloklandığında pes etme — `evolve_payload` ile varyant üret, çalışan
> varyantı `record_payload_result(worked=true)` ile kaydet.

### (e) Exploitability Score — kalibre güven (false-positive guard / kanıt moat)
```
mcp__reasoning__exploitability_score(technique, validator_confidence, reflexion_verdict,
                                     severity, evidence)
   → tek kalibre skor (0-1) + band (CONFIRMED/LIKELY/POSSIBLE/UNLIKELY)
   → validator yoksa üst sınır 0.65: deterministik doğrulama OLMADAN "CONFIRMED" deme
```
> Rapor/triage öncesi her bulguyu skorla. CONFIRMED yalnızca validator confidence ile
> mümkün → false-positive'siz, yayınlanabilir kanıt.


## (c) Auto-Skill Router — doğru skill'i deterministik seç
```
mcp__reasoning__recommend_skills(target, context, fingerprint, top_n)
   → hedef parmak izine göre HANGİ skill (/web-exploit, /active-directory, /cloud-exploitation...)
   → tam tetikleme komutu (/skill <hedef>) + kickoff. Modelin skill tetikleme tutarsızlığını çözer.
```
> `deep_think` ZATEN step_0'da `recommend_skills`'i çağırır → tek komutta keşif→zincir→
> doğrula→skorla. Slash command (kickoff) modelden bağımsız EN GÜVENİLİR tetikleme yoludur.

## Kurallar
- Karmaşık/belirsiz/yeni görevde **ilk çağrı `deep_think`** olmalı.
- Reflexion onayı ≠ kanıt; **validator** olmadan "kesin" deme.
- Her denemeyi `record_lesson` ile kaydet — atlanırsa beyin öğrenemez.
- Modeller env ile güçlendirilebilir: `CCO_REASON_MODEL`, `CCO_CRITIC_MODEL`
  (örn. daha güçlü reasoning modeline geç). **DeepSeek desteklenir:** `DEEPSEEK_API_KEY`
  ayarlıysa beyin otomatik DeepSeek'e geçer (actor=`deepseek-reasoner`, critic=`deepseek-chat`);
  yoksa OpenRouter Qwen/Hermes. LLM yoksa EV/dersler yine çalışır.

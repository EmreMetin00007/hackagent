---
name: deep-reasoning
description: "CCO'nun güçlü 'beyin' katmanı (biliş motoru). Kompleks, belirsiz veya yüksek-değerli görevlerde DERİN DÜŞÜNME yapar: ilgili geçmiş dersleri hatırlar (kalıcı öğrenme), Bayesçi beklenen-değer ile saldırı planı kurar (tree-of-thought) ve seçilen yolu Reflexion (actor→critic→validator→retry) ile kendini-düzelterek sağlamlaştırır. Bu skill'i şu durumlarda kullan: yeni bir hedefe/engagement'a başlarken; 'nereden başlamalıyım', 'en yüksek impact ne', 'sonraki adım', 'plan', 'strateji', 'düşün', 'analiz et' dendiğinde; bir exploit/PoC üretmeden önce kendini eleştirmek istediğinde; bir vektör başarısız olup strateji değiştirmen gerektiğinde. Tek kapı: deep_think. Tool sonrası daima validator ile doğrula ve record_lesson ile öğren."
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

## Kurallar
- Karmaşık/belirsiz/yeni görevde **ilk çağrı `deep_think`** olmalı.
- Reflexion onayı ≠ kanıt; **validator** olmadan "kesin" deme.
- Her denemeyi `record_lesson` ile kaydet — atlanırsa beyin öğrenemez.
- Modeller env ile güçlendirilebilir: `CCO_REASON_MODEL`, `CCO_CRITIC_MODEL`
  (örn. daha güçlü reasoning modeline geç). LLM yoksa EV/dersler yine çalışır.

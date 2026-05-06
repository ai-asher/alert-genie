---
alertnames: [HighMemoryUsage, OOMKilled]
keywords: [memory, OOM, heap]
tags: [k8s, resource]
summary: Standard procedure for high memory / OOM situations on K8s pods
---

# High Memory Usage / OOM

Standard remediation playbook.

## Diagnosis
1. Check pod memory limits vs actual usage in Prometheus
2. Look at recent deploy commits for memory leaks
3. Check if traffic is unusually high

## Remediation

If sustained OOM:
- First, scale up replicas to spread load: `kubectl scale deployment/<name> --replicas=<higher>`
- If that doesn't help, increase memory limit in deployment spec
- As last resort: rollback to last known good version

Avoid `kubectl delete pod` — pods will OOM again on restart unless underlying cause is addressed.

## Common root causes
- Memory leak in latest deploy
- Cache without bounds
- Large response payloads from upstream

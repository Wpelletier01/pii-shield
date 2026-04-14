# Zero-code PII sanitization for Grafana Loki and Promtail in Kubernetes

If you use Grafana Loki for log aggregation, you probably rely on **Promtail** (or the Grafana Agent) to scrape your Kubernetes pods and ship the logs. Loki is famously cost-effective because it only indexes metadata (labels), keeping the actual log text raw.

However, this raw text architecture makes PII (Personally Identifiable Information) and secret leakage a critical issue. If your applications log user emails, credit cards, or API keys, that data is permanently stored in Loki chunk files (often in deeply integrated S3/GCS buckets) making it incredibly hard to comply with GDPR "Right to be Forgotten" requests.

## The Standard Promtail Approach: `pipeline_stages` Regex

The official Grafana way to handle sensitive data is using Promtail's `pipeline_stages` to scrub data before it reaches Loki. A typical Promtail config looks like this:

```yaml
pipeline_stages:
  - match:
      selector: '{app="my-service"}'
      stages:
        - regex:
            expression: '(?P<email>[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
        - replace:
            source: email
            expression: '(.*)'
            replace: '[REDACTED]'
```

### Why this approach breaks down at scale:

1. **The Regex Trap:** You have to write and maintain complex regular expressions for every type of sensitive data (API keys, passwords, custom tokens). If a new format appears, your Promtail config is instantly outdated and secrets leak.
2. **CPU and Latency:** Running heavily nested regex `pipeline_stages` on high-throughput log streams puts massive CPU pressure on the node running Promtail. Promtail can quickly throttle or consume too much memory when evaluating hundreds of regex rules against every log line.
3. **Loss of Context:** When you replace a secret with `[REDACTED]`, you lose the ability to track an entity. If you need to trace why a specific (but anonymous) user experienced 50 errors, you can't, because all users now just look like `[REDACTED]`.

## The Zero-Code Alternative: PII-Shield Sidecar

Instead of forcing Promtail to do the heavy lifting of parsing and regex matching, you can shift the responsibility to a dedicated, high-performance sidecar next to your application: **PII-Shield**.

PII-Shield intercepts the log stream *before* Promtail even sees it.

### How it works:
1. **The App** writes logs to a shared volume file instead of `stdout`.
2. **PII-Shield (Sidecar)** tails that file, scrubs it using zero-allocation Go routines and mathematical entropy detection (no regex needed for API keys!), and prints the *clean* logs to its own `stdout`.
3. **Promtail** natively scrapes the sidecar's `stdout` just like any other container.

Promtail needs **zero configuration changes**. It just blindly ships the logs to Loki, completely unaware that the heavy sanitization has already occurred.

### Kubernetes Implementation

Here is how you configure the pod natively. Note that Promtail, by default, reads from `/var/log/containers/*.log` via Kubernetes Service Discovery. It will automatically find the `pii-shield-sidecar` output.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: billing-service
  labels:
    app: billing
spec:
  containers:
    - name: billing-app
      image: billing-app:v2.1.0
      # The app writes its private output to a shared pipe/file
      command: ["/bin/sh", "-c"]
      args: ["./billing-binary > /var/run/logs/app.log"]
      volumeMounts:
        - name: log-volume
          mountPath: /var/run/logs

    - name: pii-shield-sidecar
      image: thelisdeep/pii-shield:v1.2.3
      env:
        - name: PII_SALT
          value: "grafana-secure-salt"
      # PII-Shield reads, scrubs, and outputs to stdout for Promtail to pick up
      command: ["/bin/sh", "-c"]
      args: ["tail -n +1 -f /var/run/logs/app.log | pii-shield"]
      volumeMounts:
        - name: log-volume
          mountPath: /var/run/logs

  volumes:
    - name: log-volume
      emptyDir: {}
```

*Pro tip: The `thelisdeep/pii-shield` image is multi-arch (`amd64`/`arm64`).*

### Why this is the ultimate Loki stack upgrade:

* **Zero Promtail Pipelines:** You can delete hundreds of lines of brittle `pipeline_stages` from your Promtail DaemonSet. Promtail goes back to doing what it does best: shipping logs.
* **Deterministic Hashing:** PII-Shield replaces secrets with a stable HMAC using the `PII_SALT`, (e.g., `[HIDDEN:e9f1a2]`). In Loki's LogQL, you can now trace an exact user workflow `|= "[HIDDEN:e9f1a2]"` across microservices without actually knowing their email or token.
* **Smart Entropy Detection:** Unlike Promtail regexes, PII-Shield mathematically calculates Shannon Entropy. It will automatically detect a newly issued 64-character API key it has never seen before and mask it, preventing 0-day log leaks.
* **Micro-footprint:** PII-Shield uses <30Mi of memory, making it incredibly cheap to run as a sidecar.

---

**Protect your Grafana Loki data retention today.** 
Check out the [PII-Shield repository on GitHub](https://github.com/thelisdeep/pii-shield) and drop a star if this simplifies your Kubernetes logging!

# Zero-code PII sanitization for Elasticsearch, Logstash, and Kibana (ELK) in Kubernetes

The ELK Stack (Elasticsearch, Logstash, Kibana) remains the undisputed heavy-weight champion of enterprise log management. However, its greatest strength—powerful full-text indexing and visualization—is also its biggest privacy liability. 

If Personally Identifiable Information (PII) like emails, credit card data, or internal API tokens make it into Elasticsearch, that sensitive data becomes globally searchable. Not only does this expose secrets to unauthorized staff via Kibana dashboards, but it also creates a massive GDPR compliance disaster that often requires painful re-indexing to fix.

## The Standard Logstash Approach: `grok` and `gsub`

The traditional defense mechanism in the ELK ecosystem is to filter data centrally using Logstash (or Fluentd/Filebeat processors) before it hits Elasticsearch. A typical Logstash pipeline relies heavily on the `mutate` filter and regex substitution:

```logstash
filter {
  if [kubernetes][labels][app] == "payment-service" {
    mutate {
      gsub => [
        # Match emails
        "message", "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]",
        # Match generic API tokens
        "message", "Bearer [a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "Bearer [REDACTED_TOKEN]"
      ]
    }
  }
}
```

### Why central Logstash filtering breaks down:

1. **The CPU Bottleneck:** Logstash is notoriously resource-intensive (running on the JVM). Forcing it to execute complex regex `gsub` operations over millions of log lines per minute creates severe bottlenecks, forcing you to scale up expensive central Logstash clusters.
2. **The Whack-a-Mole Game:** You are forced to maintain a colossal, ever-growing list of regex patterns for every new token format your microservices invent. 
3. **Loss of Kibana Tracing:** If you blindly replace every email with `[REDACTED]`, your support engineers lose the ability to track a user's journey through Kibana. You can't filter a dashboard to see the timeline of a specific user if all users look identical.

## The Edge Defense: PII-Shield Sidecar

Instead of battling regex bottlenecks at the center of your ELK pipeline, you can sanitize data at the absolute edge—within the Kubernetes pod itself—using **PII-Shield**.

PII-Shield intercepts the application's output, scrubs it at blinding speed using Go-based entropy detection, and then passes it safely to `stdout` for your DaemonSet (Filebeat or Fluentd) to collect and ship to Logstash.

### The Result:

<div class="code-block-wrapper" style="margin-bottom: 1.5rem;">
    <pre><code style="color: #a5d6ff;">// What your app generated:
{"level":"info", "message":"Processing payout", "email":"john.doe@gmail.com", "stripe_key":"sk_live_51Mabc..."}

// What Filebeat ships to Logstash and Elasticsearch:
{"level":"info", "message":"Processing payout", "email":"[HIDDEN:e9f1a2]", "stripe_key":"[REDACTED:entropy]"}</code></pre>
</div>

### How it works:
1. **The App** redirects its output to an ephemeral shared volume (like an `emptyDir`) instead of the main `stdout`.
2. **PII-Shield (Sidecar)** tails that ephemeral file, scrubs it using zero-allocation Go routines and mathematical entropy detection (no regex needed for API keys!), and prints the *clean* logs to its own `stdout`.
3. **Filebeat/Fluentd** natively scrapes the sidecar's `stdout` just like any regular container log.

Your ELK pipeline needs **zero configuration changes**. Data arrives at Logstash already sanitized.

### Kubernetes Implementation

Here is how you configure the pod natively. Since Filebeat reads `/var/log/containers/*.log`, it automatically discovers the sidecar's clean output.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payment-service
  labels:
    app: payments
spec:
  containers:
    - name: payment-app
      image: payment-app:v3.0.0
      # The app writes its private output to an ephemeral pipe/file
      command: ["/bin/sh", "-c"]
      args: ["./payment-binary > /var/run/logs/app.log"]
      volumeMounts:
        - name: log-volume
          mountPath: /var/run/logs

    - name: pii-shield-sidecar
      image: thelisdeep/pii-shield:v1.2.3
      env:
        - name: PII_SALT
          value: "elk-secure-salt"
      # PII-Shield reads, scrubs, and outputs to stdout for Filebeat to pick up
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

### Why this is the ultimate ELK upgrade:

* **Save Massive Logstash CPU Costs:** By offloading regex string manipulation to distributed Go sidecars, your Logstash clusters only need to route and parse JSON, allowing you to downsize your central logging infrastructure.
* **Deterministic Hashing for Kibana:** PII-Shield replaces identifiers with stable HMAC hashes using the `PII_SALT` (e.g., `[HIDDEN:e9f1a2]`). In Kibana, you can now build dashboards or filter Discover search results by exactly `email: "[HIDDEN:e9f1a2]"` to track a workflow without legally compromising the user.
* **Smart Entropy Detection:** Unlike manual `gsub` regexes, PII-Shield mathematically calculates Shannon Entropy to automatically detect and redact unknown API keys and secrets in real-time.
* **Micro-footprint at the Edge:** PII-Shield uses <30Mi of memory, keeping your application pods lightweight.

---

**Keep your Elasticsearch indices compliant and clean.** 
Check out the [PII-Shield repository on GitHub](https://github.com/thelisdeep/pii-shield) and drop a star if this simplifies your ELK observability stack!

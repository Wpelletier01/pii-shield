package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aragossa/pii-shield/pkg/metrics"
	"github.com/aragossa/pii-shield/pkg/scanner"
)

func main() {
	metricsEnabled := os.Getenv("PII_METRICS_ENABLED") == "true"
	if metricsEnabled {
		port := os.Getenv("PII_METRICS_PORT")
		if port == "" {
			port = "9090"
		}
		
		// Wire metrics callback
		scanner.RedactionCallback = metrics.IncrementRedaction

		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Printf("Starting Prometheus metrics server on :%s", port)
			if err := http.ListenAndServe(":"+port, nil); err != nil {
				log.Printf("Metrics server failed: %v", err)
			}
		}()
	}

	// Use buffered input for speed
	reader := bufio.NewScanner(os.Stdin)

	// Optional: Increase buffer if log lines can be huge
	// buf := make([]byte, 0, 64*1024)
	// reader.Buffer(buf, 1024*1024)

	for reader.Scan() {
		text := reader.Text()

		var start time.Time
		if metricsEnabled {
			start = time.Now()
			metrics.ProcessedBytesTotal.Add(float64(len(text)))
		}

		// Core logic
		cleaned := scanner.ScanAndRedact(text)

		if metricsEnabled {
			metrics.ProcessingDuration.Observe(time.Since(start).Seconds())
		}

		// Write back to Stdout for Fluentd/Logstash
		fmt.Println(cleaned)
	}

	if err := reader.Err(); err != nil {
		if metricsEnabled {
			metrics.ErrorsTotal.Inc()
		}
		fmt.Fprintln(os.Stderr, "Error reading standard input:", err)
		os.Exit(1)
	}
}

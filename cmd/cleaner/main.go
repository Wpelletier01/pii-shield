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

	failPolicy := os.Getenv("PII_FAIL_POLICY")
	if failPolicy == "" {
		failPolicy = "open" // Start with fail-open by default 
	}

	// Use buffered input
	reader := bufio.NewScanner(os.Stdin)

	// Explicit memory limits. Buffer size to avoid OOM but allow large JSONs (up to 10MB)
	buf := make([]byte, 1024*1024)
	reader.Buffer(buf, 10*1024*1024)

	for reader.Scan() {
		text := reader.Text()

		// Functional wrapper to catch panics per-line
		func() {
			defer func() {
				if r := recover(); r != nil {
					if metricsEnabled {
						metrics.ErrorsTotal.Inc()
					}
					// Apply Blast Radius Control Policy
					if failPolicy == "closed" {
						fmt.Println("[PII_SHIELD_DROP: FATAL_ERROR]")
					} else {
						// Fail-Open: keep the flow alive 
						fmt.Println(text)
					}
				}
			}()

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
		}()
	}

	if err := reader.Err(); err != nil {
		if metricsEnabled {
			metrics.ErrorsTotal.Inc()
		}
		if err == bufio.ErrTooLong {
			if failPolicy == "closed" {
				fmt.Println("[PII_SHIELD_DROP: BUFFER_OVERFLOW]")
			} else {
				// Flow broken, but we can log that we failed open. However, we can't emit the rest of the line because scanner stopped.
				fmt.Println("[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")
			}
		}
		fmt.Fprintln(os.Stderr, "Error reading standard input:", err)
		os.Exit(1)
	}
}

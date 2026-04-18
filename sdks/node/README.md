# @aragossa/pii-shield-wasi

High-performance PII redaction scanner powered by a core Go engine compiled to WebAssembly (WASI). It provides lightning-fast text analysis with hybrid heuristic and entropy-based validation.

## Installation

```bash
npm install @aragossa/pii-shield-wasi
```

## Usage

```javascript
const { Scanner } = require('@aragossa/pii-shield-wasi');

// Initialize the scanner with optional configuration overrides
const scanner = new Scanner({
    entropy_threshold: 4.0,
    confidence_score: 0.8
});

const text = "Connecting to DB with api_key: aB3$xyz890LmnopQ";
const redactedText = scanner.redact(text);

console.log(redactedText);
// Output will have the high entropy token redacted
```

## Features

- **Blazing Fast**: Runs a highly optimized Go WASM binary in NodeJS natively.
- **Zero-Allocation**: Hot-paths have been optimized to prevent garbage collection overhead during large log streaming.
- **Hybrid Scoring**: Combines static whitelists, regex heuristics, and Shannon entropy for zero false-positives on things like UUIDs and IPv6 addresses.

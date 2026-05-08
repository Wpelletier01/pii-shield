package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProcessJSONLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string // substrings expected in output
		isOk     bool
	}{
		{
			name:     "invalid json",
			input:    "{invalid",
			expected: nil,
			isOk:     false,
		},
		{
			name:     "simple map with sensitive key",
			input:    `{"password": "mysecretpassword", "safe": "value"}`,
			expected: []string{`"[HIDDEN`},
			isOk:     true,
		},
		{
			name:     "generic kv pair string value",
			input:    `{"key": "password", "value": "mysecretpassword"}`,
			expected: []string{`"[HIDDEN`},
			isOk:     true,
		},
		{
			name:     "generic kv pair int value",
			input:    `{"key": "cvv", "value": 123}`,
			expected: []string{`"value":0`},
			isOk:     true,
		},
		{
			name:     "generic kv pair float value",
			input:    `{"key": "cvv", "value": 123.45}`,
			expected: []string{`"value":0`},
			isOk:     true,
		},
		{
			name:     "nested slice string",
			input:    `{"data": ["safe_string", {"secret_key": "highly_sensitive_data_here"} ]}`,
			expected: []string{`"[HIDDEN`},
			isOk:     true,
		},
		{
			name:     "nested slice numbers",
			input:    `{"data": [123, 123.45]}`,
			expected: []string{`123`, `123.45`}, // Ensure they don't get zeroed out unless sensitive
			isOk:     true,
		},
		{
			name:     "map with ints and floats",
			input:    `{"cvv": 123, "amount": 42.42, "secret_float": 456.78}`,
			expected: []string{`"cvv":0`, `"amount":42.42`, `"secret_float":0`},
			isOk:     true,
		},
		{
			name:     "slice with luhn string",
			input:    `{"data": ["4556737586899855"]}`, // A luhn string inside an array
			expected: []string{`"[HIDDEN`},
			isOk:     true,
		},
		{
			name:     "2d slice string",
			input:    `{"data": [["safe_string", "4556737586899855"]]}`,
			expected: []string{`"[HIDDEN`},
			isOk:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := processJSONLine(tt.input)
			if ok != tt.isOk {
				t.Fatalf("expected ok=%v, got %v", tt.isOk, ok)
			}
			if tt.isOk {
				for _, exp := range tt.expected {
					if exp != "" && !strings.Contains(got, exp) {
						t.Errorf("expected output to contain %q, but got %q", exp, got)
					}
				}

				// Ensure it's valid JSON
				var dummy map[string]interface{}
				if err := json.Unmarshal([]byte(got), &dummy); err != nil {
					t.Errorf("output is not valid JSON: %v. Output: %s", err, got)
				}
			}
		})
	}
}

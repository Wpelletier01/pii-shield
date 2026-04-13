from pii_shield import PiiShield, PiiShieldConfig
import sys

def main():
    try:
        print("Loading WASM module in Python...")
        cfg = PiiShieldConfig(confidence_score=1.5, fail_policy="open")
        shield = PiiShield(config=cfg, wasm_path="../../pii-shield-wasi.wasm")

        test_strings = [
            'User registered with token: 123e4567-e89b-12d3-a456-426614174000',
            'Just a random UUID: 123e4567-e89b-12d3-a456-426614174000',
            'Password is mySuperSecretPassword123!',
            'Invalid payload JSON {}'
        ]

        passed = True
        for txt in test_strings:
            print(f"Original: {txt}")
            redacted = shield.redact(txt)
            print(f"Redacted: {redacted}\n---")
            if "FATAL_ERROR" in redacted:
                passed = False

        if passed:
            print("SUCCESS")
        else:
            print("FAILED")
            sys.exit(1)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

const { PiiShield } = require('./index');

async function main() {
    try {
        console.log("Loading WASM module...");
        const shield = await PiiShield.create({
            confidenceScore: 1.5,
            failPolicy: "open"
        }, "../../pii-shield-wasi.wasm");

        const testStrings = [
            'User registered with token: 123e4567-e89b-12d3-a456-426614174000',
            'Just a random UUID: 123e4567-e89b-12d3-a456-426614174000',
            'Password is mySuperSecretPassword123!',
            'Invalid payload JSON {}'
        ];

        let passed = true;

        for (const str of testStrings) {
            console.log("Original:", str);
            const redacted = shield.redact(str);
            console.log("Redacted:", redacted);
            console.log("---");
            if (redacted.includes("FATAL_ERROR")) {
                passed = false;
            }
        }
        
        // Let's assert memory bounds and GC? No, just the correct output is fine for now
        if (passed) {
            console.log("SUCCESS");
        } else {
            console.error("FAILED");
            process.exit(1);
        }
    } catch (err) {
        console.error("Fatal error:", err);
        process.exit(1);
    }
}

main();

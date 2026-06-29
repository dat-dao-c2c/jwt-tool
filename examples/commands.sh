#!/bin/bash
# JWT Tool Usage Examples

# 1. Setup
# Ensure jwt-tool is linked: npm link
SECRET="mysecret"
TOKEN=$(jwt-tool generate-secret --length 32 | tr -d '\n')
# Generate a simple token for demonstration purposes
TEST_TOKEN=$(jwt-tool generate '{"sub": "123", "iat": 1782723369}' "$SECRET")
echo "Test Token: $TEST_TOKEN"
echo -e "wrong\n$SECRET\nsecret" > wordlist.txt

# 2. Decode & Inspect
echo "--- Decoding ---"
jwt-tool decode "$TEST_TOKEN"

# 3. Console Report
echo "--- Console Report ---"
jwt-tool decode "$TEST_TOKEN" --report

# 4. Security Analysis
echo "--- Analysis ---"
jwt-tool analyze "$TEST_TOKEN"

# 5. Secret Generation
echo "--- Generate Secret ---"
NEW_SECRET=$(jwt-tool generate-secret --length 32)
echo "New Secret: $NEW_SECRET"

# 6. Evaluate Secret
echo "--- Evaluate Secret ---"
jwt-tool evaluate-secret "$NEW_SECRET"

# 7. Crack Secret
echo "--- Crack Secret ---"
jwt-tool crack "$TEST_TOKEN" wordlist.txt

# Cleanup
rm wordlist.txt

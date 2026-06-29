# JWT Tool

A CLI tool to decode, analyze, and crack HS256 JSON Web Tokens (JWTs).

## Features

- **Decode**: Decode JWTs and view header, payload, and signature.
- **Analyze**: Perform security analysis on tokens (checks algorithm strength, missing claims like `exp`, `iat`, `jti`).
- **Crack**: Brute-force HS256 JWT secrets using a wordlist.

## Installation

```bash
npm install
npm run build
# To use as a command globally:
npm link
```
After running `npm link`, you can run `jwt-tool` from anywhere in your terminal.

Alternatively, you can install it directly from the registry once published:
```bash
npm install -g jwt-tool
```

## Usage

Assuming you have run `npm link`, you can use the tool as `jwt-tool`.

### 1. Decode a JWT (JSON Output)
```bash
jwt-tool decode <token>
# Result: JSON output with header, payload, signature, and security analysis.
```

### 2. Decode a JWT (Console Report)
```bash
jwt-tool decode <token> --report
# Result: A human-readable, colorized terminal report of security findings.
```

### 3. Analyze a JWT
```bash
jwt-tool analyze <token>
# Result: A concise JSON object containing security score and specific findings.
```

### 4. Crack a JWT
Brute-force an HS256 secret using a wordlist file.

```bash
# First, fetch a wordlist (e.g., from wallarm/jwt-secrets)
curl -L https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list -o jwt.secrets.list
# https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/refs/heads/master/Real-Passwords/Top304Thousand-probable-v2.txt

# Run the crack command
jwt-tool crack <token> jwt.secrets.list
```
# Result: Output showing the found secret or a failure message.

### 5. Generate a Strong Secret
Generate a cryptographically strong random secret key.

```bash
jwt-tool generate-secret --length 32
# Result: A secure random string.
```

### 6. Evaluate Secret Strength
Assess the strength of a secret key based on length and complexity.

```bash
jwt-tool evaluate-secret <secret>
# Result: A score (0-100) and feedback on how to improve the secret's strength.
```

For more hands-on practice, see `examples/commands.sh`.

## Common Use Cases

- **Troubleshooting Token Rejections**: Quickly inspect a token's claims (`exp`, `iat`, `sub`) to diagnose why an authentication call might be failing.
- **Automated Security Auditing**: Integrate the `analyze` command into your CI/CD pipelines to automatically reject tokens with weak algorithms (e.g., `HS256`) or missing mandatory security claims.
- **Credential Recovery**: If an internal testing environment has lost its signing secret, use the `crack` command with a wordlist to recover it.
- **Quick Token Inspection**: Instead of uploading tokens to public websites like `jwt.io` (which may be insecure for proprietary tokens), use `jwt-tool` to inspect tokens locally and securely.

## CI/CD Pipeline Examples

### 1. Security Gate: Fail Build on Low Score
Use the `analyze` command to fail a pipeline if a JWT does not meet minimum security requirements.

```bash
# Example: Exit with error if score is less than 80
SCORE=$(jwt-tool analyze "$MY_JWT" | jq '.score')
if [ "$SCORE" -lt 80 ]; then
  echo "Security threshold not met (Score: $SCORE). Failing build."
  exit 1
fi
```

### 2. Secret Strength Validation
Ensure that your infrastructure secrets meet complexity requirements before they are committed or used.

```bash
# Example: Evaluate a secret from environment variables
SCORE=$(jwt-tool evaluate-secret "$APP_SECRET" | grep -oE '[0-9]+')

if [ "$SCORE" -lt 80 ]; then
  echo "Weak secret detected!"
  exit 1
fi
```

## Recommended JWT Configuration
To achieve the highest security score, aim for tokens that include:

- **Strong Algorithm**: Use asymmetric algorithms like `RS256` (RSA) or `ES256` (ECDSA) instead of symmetric ones (`HS256`).
- **Mandatory Claims**:
  - `exp`: Defines when the token expires (essential to limit window of misuse).
  - `iat`: Helps track when the token was issued.
  - `jti`: A unique identifier for the token (crucial for detecting and preventing replay attacks).
  - `iss`: Identifies the issuer of the token.
  - `aud`: Specifies the intended audience for the token.

### Best Practice Example (Payload)

```json
{
  "sub": "user_1234567890",
  "name": "John Doe",
  "admin": false,
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "iat": 1715000000,
  "exp": 1715003600,
  "jti": "unique-token-identifier-98765"
}
```

## Running Tests

We use `vitest` to ensure code quality.

```bash
npm run test
```

You can find the test suites in the `tests/` directory:

- `tests/analyzer.test.ts`: Tests security analysis logic.
- `tests/secret.test.ts`: Tests secret generation and evaluation logic.

## Security Note

This tool is for educational and security testing purposes only. Always use authorized testing methods.

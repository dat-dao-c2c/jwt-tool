# JWT Tool

A CLI tool to decode, analyze, and crack HS256 JSON Web Tokens (JWTs).

## Features

- **Generate Secret**: Create cryptographically strong random signing secrets.
- **Evaluate Secret**: Score a secret's strength by estimated entropy (length × charset).
- **Generate**: Create new JWTs with custom payloads, algorithms, and expiry.
- **Verify**: Validate JWT signatures using a secret or public key, with algorithm pinning to prevent confusion attacks.
- **Analyze**: Security-score tokens against OWASP guidance — flags `alg:none`/`crit`, key-injection headers (`jwk`/`jku`/`x5u`/`x5c`), missing `typ`, expiry/`nbf`, long-lived tokens, sensitive payload data, and missing `iat`/`jti`/`iss`/`aud`/`sub`. Supports `--fail-on` for CI gating.
- **Decode**: Decode JWTs and view header, payload, and signature, as JSON or a colorized report.
- **Crack**: Brute-force HS256 JWT secrets using a wordlist from a file, an `http(s)://` URL, or stdin.
- **Flexible input**: Pass tokens/keys inline, from a file (`@path`), or via stdin (`-`).

## Installation

Install globally from npm (provides the `jwt-tool` command):
```bash
npm install -g @datdm198x/jwt-tool
```

Or run it without installing:
```bash
npx @datdm198x/jwt-tool decode <token>
```

### From source (development)
```bash
npm install
npm run build
# To use as a command globally:
npm link
```
After running `npm link`, you can run `jwt-tool` from anywhere in your terminal.

## Usage

Once installed globally (`npm install -g @datdm198x/jwt-tool`) or linked from
source, use the tool as `jwt-tool`.

### 1. Best Practice Example (Payload)

A well-formed token that scores highly includes the standard registered claims.
The example below uses `jsonc` (JSON with comments) for readability — a real JWT
payload is strict JSON and must not contain comments.

```jsonc
{
  "sub": "user_1234567890",              // Subject: the unique ID of the user/entity the token represents
  "name": "John Doe",                    // Custom claim: display name (avoid sensitive/PII data — payloads are only base64url-encoded, not encrypted)
  "admin": false,                        // Custom claim: application authorization flag (validated server-side, never trusted blindly)
  "iss": "https://auth.example.com",     // Issuer: who signed the token; validate against an allowlist of trusted issuers
  "aud": "https://api.example.com",      // Audience: the intended recipient; each service must reject tokens not addressed to it
  "iat": 1715000000,                     // Issued At (Unix seconds): creation time; enables "reject tokens issued before X" checks
  "exp": 1715003600,                     // Expiration (Unix seconds): here iat + 3600 = a 1-hour lifetime; keep it short
  "jti": "unique-token-identifier-98765" // JWT ID: unique per token; enables replay protection / revocation deny-lists
}
```

### 2. Generate a Strong Secret
Generate a cryptographically strong random secret key.

```bash
jwt-tool generate-secret --length 64
# Result: A secure random string.
```

### 3. Evaluate Secret Strength
Assess the strength of a secret key based on estimated entropy (length × charset),
where 128 bits maps to a full score.

```bash
jwt-tool evaluate-secret <secret>
# Result: A score (0-100), an entropy estimate, and feedback for improvement.
```

### 4. Generate a JWT
```bash
iat=$(date +%s)
exp=$((iat + 3600))  # expires in 1 hour
jwt-tool generate "$(printf '%s' "{
  \"sub\": \"user_1234567890\",
  \"name\": \"John Doe\",
  \"admin\": false,
  \"iss\": \"https://auth.example.com\",
  \"aud\": \"https://api.example.com\",
  \"iat\": $iat,
  \"exp\": $exp,
  \"jti\": \"unique-token-identifier-98765\"
}")" '9MI9lxf9CkqJsLBvgRmmlB2swiEauhpMJgL0I_XDDh58JaubL47M90t3CXbHKsG98Dzyp-G0Zub8vIbk7hvCXw' --alg HS256

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6ZmFsc2UsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tIiwiaWF0IjoxNzkwNzM1Nzc4LCJleHAiOjE3OTA3MzkzNzgsImp0aSI6InVuaXF1ZS10b2tlbi1pZGVudGlmaWVyLTk4NzY1In0.TFlR4z_guGg3z6CXJQvI9AJX1SULEgRihumAbWSp66o

# Set an expiry and/or sign with a private key file:
jwt-tool generate '{
  "sub": "user_1234567890",
  "name": "John Doe",
  "admin": false,
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "iat": 1715000000,
  "exp": 1715003600,
  "jti": "unique-token-identifier-98765"
}' --key-file private.pem --alg RS256 --expires-in 1h
# Result: The generated JWT string.
```

### 5. Verify a JWT
```bash
jwt-tool verify <token> <secret>
# Result: A JSON object indicating validity (true/false) and the payload or error message.

# Verify against an asymmetric public key and pin the accepted algorithm(s):
jwt-tool verify <token> --key-file public.pem --alg RS256
```
> Algorithms are pinned to the token's `alg` by default (or to `--alg`) to
> prevent algorithm-confusion attacks.

### 6. Analyze a JWT
```bash
jwt-tool analyze <token>
# Result: A concise JSON object containing security score and specific findings.

# Fail a CI job when a finding at or above a severity is present:
jwt-tool analyze <token> --fail-on critical
# Exit codes: 0 = clean / below threshold, 2 = threshold met, 1 = usage/decode error.
```

The analyzer checks the algorithm (`none`/`crit`), key-injection headers
(`jwk`/`jku`/`x5u`/`x5c`), the `typ` header, expiry (`exp`), not-before (`nbf`),
long-lived tokens, sensitive data in the payload, and the presence of `iat`,
`jti`, `iss`, `aud`, and `sub`.

Tokens can be passed inline, from a file with `@path`, or from stdin with `-`:
```bash
echo "$TOKEN" | jwt-tool analyze -
jwt-tool decode @token.txt --report
```

### 7. Decode a JWT
```bash
# JSON output with header, payload, signature, and security analysis:
jwt-tool decode <token>

# Human-readable, colorized terminal report of security findings:
jwt-tool decode <token> --report
```

### 8. Crack a JWT
Brute-force an HS256 secret using a wordlist. The wordlist source can be a **file
path**, an **`http(s)://` URL**, or **`-` (stdin)** — so you don't have to save it
to disk first. Non-HMAC tokens are rejected up front, and progress is reported for
large lists.

```bash
# From a local file
curl -L https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list -o jwt.secrets.list
jwt-tool crack <token> jwt.secrets.list

# Directly from a public URL (streamed, no local file)
jwt-tool crack <token> https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list

# From stdin — ideal for authenticated/private sources (no auth headers are sent
# by the built-in URL fetch, so pipe the fetched content in instead):
gh api repos/OWNER/REPO/contents/jwt.secrets.list -H "Accept: application/vnd.github.raw" \
  | jwt-tool crack <token> -
```
# Result: Output showing the found secret (with attempt count) or a failure message.

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
  - **`exp` (Expiration Time):** Prevents indefinite token validity. Essential for limiting the impact of a compromised token by ensuring it becomes unusable after a defined period.
  - **`iat` (Issued At):** Establishes the token's creation time. Used to implement "time-of-issuance" validation, allowing servers to reject tokens issued before a specific timestamp (e.g., to revoke access after a password reset).
  - **`jti` (JWT ID):** Provides a unique ID to prevent replay attacks. Allows servers to implement a "blacklist" or "used-tokens" cache to ensure a single-use token cannot be re-submitted.
  - **`iss` (Issuer):** Validates the trusted source. Enables the service to verify that the token was signed by the expected authentication provider.
  - **`aud` (Audience):** Ensures the token is used only for authorized services. Prevents a token issued for one service from being maliciously re-used to authenticate against a more sensitive or different microservice.

For a concrete, per-field payload example, see [Best Practice Example (Payload)](#1-best-practice-example-payload) above.

## Running Tests

We use `vitest` to ensure code quality.

```bash
npm run test
```

You can find the test suites in the `tests/` directory:

- `tests/analyzer.test.ts`: Tests security analysis logic.
- `tests/secret.test.ts`: Tests secret generation and evaluation logic.
- `tests/cracker.test.ts`: Tests wordlist cracking and algorithm detection.

## Security Note

This tool is for educational and security testing purposes only. Always use authorized testing methods.

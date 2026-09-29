import type { Jwt, JwtPayload } from 'jsonwebtoken';
import chalk from 'chalk';

export type Severity = 'critical' | 'warning' | 'info';

export interface Finding {
  category: 'Header' | 'Claim' | 'Algorithm';
  severity: Severity;
  message: string;
}

export interface Analysis {
  score: number;
  findings: Finding[];
}

const HMAC_ALGS = ['HS256', 'HS384', 'HS512'];

// Headers that can carry attacker-controlled verification key material.
// Per OWASP, the verification key must never be taken from the token itself
// unless it chains to a trusted root. (jku/x5u also enable SSRF.)
const KEY_INJECTION_HEADERS = ['jwk', 'jku', 'x5u', 'x5c'] as const;

// Recommended maximum access-token lifetime before we flag it as long-lived.
const MAX_RECOMMENDED_LIFETIME_SECONDS = 24 * 60 * 60; // 24h

// Payload keys that should not travel inside a (typically unencrypted) JWT.
const SENSITIVE_CLAIM_KEYS = [
  'password', 'passwd', 'secret', 'api_key', 'apikey', 'access_key',
  'private_key', 'privatekey', 'ssn', 'credit_card', 'creditcard', 'cvv', 'pin',
];

function formatTimestamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export function analyzeJwt(decoded: Jwt): Analysis {
  const { header, payload } = decoded;
  const findings: Finding[] = [];
  let score = 100;

  const nowSeconds = Date.now() / 1000;

  // Header / Algorithm analysis
  if (header.crit) {
    findings.push({ category: 'Header', severity: 'critical', message: 'Contains "crit" header (potential attack vector).' });
    score -= 40;
  }

  if (!header.alg || header.alg === 'none') {
    findings.push({ category: 'Algorithm', severity: 'critical', message: 'Algorithm is "none" or missing (signature not enforced).' });
    score -= 50;
  } else if (HMAC_ALGS.includes(header.alg)) {
    findings.push({ category: 'Algorithm', severity: 'warning', message: `Symmetric algorithm ${header.alg} used (ensure the signing secret is strong).` });
    score -= 10;
  }

  for (const h of KEY_INJECTION_HEADERS) {
    if ((header as Record<string, unknown>)[h] !== undefined) {
      findings.push({
        category: 'Header',
        severity: 'critical',
        message: `Contains "${h}" header (attacker-controllable verification key; never trust key material from the token).`,
      });
      score -= 40;
    }
  }

  if ((header as Record<string, unknown>).typ === undefined) {
    findings.push({ category: 'Header', severity: 'info', message: 'Missing "typ" header (recommended to prevent token type confusion).' });
    score -= 5;
  }

  // Claim analysis
  const payloadData = payload as JwtPayload;

  if (payloadData.exp === undefined) {
    findings.push({ category: 'Claim', severity: 'critical', message: 'Missing "exp" (expiry) claim.' });
    score -= 30;
  } else if (payloadData.exp < nowSeconds) {
    findings.push({ category: 'Claim', severity: 'critical', message: `Token is expired (exp: ${formatTimestamp(payloadData.exp)}).` });
    score -= 20;
  } else {
    // Long-lived tokens widen the exposure window if leaked (OWASP: prefer short lifetimes).
    const lifetime = payloadData.exp - (payloadData.iat ?? nowSeconds);
    if (lifetime > MAX_RECOMMENDED_LIFETIME_SECONDS) {
      const hours = Math.round(lifetime / 3600);
      findings.push({ category: 'Claim', severity: 'info', message: `Long-lived token (~${hours}h); prefer short expiry times.` });
      score -= 5;
    }
  }

  if (payloadData.nbf !== undefined && payloadData.nbf > nowSeconds) {
    findings.push({ category: 'Claim', severity: 'warning', message: `Token is not yet valid (nbf: ${formatTimestamp(payloadData.nbf)}).` });
    score -= 10;
  }

  if (payloadData.iat === undefined) {
    findings.push({ category: 'Claim', severity: 'warning', message: 'Missing "iat" (issued at) claim.' });
    score -= 10;
  }

  if (payloadData.jti === undefined) {
    findings.push({ category: 'Claim', severity: 'info', message: 'Missing "jti" (JWT ID) claim (recommended for replay protection).' });
    score -= 5;
  }

  if (payloadData.iss === undefined) {
    findings.push({ category: 'Claim', severity: 'warning', message: 'Missing "iss" (issuer) claim (should be present and validated against an allowlist).' });
    score -= 10;
  }

  if (payloadData.aud === undefined) {
    findings.push({ category: 'Claim', severity: 'warning', message: 'Missing "aud" (audience) claim (should be present and validated against the recipient).' });
    score -= 10;
  }

  if (payloadData.sub === undefined) {
    findings.push({ category: 'Claim', severity: 'info', message: 'Missing "sub" (subject) claim.' });
    score -= 5;
  }

  // Information disclosure: sensitive data should not be placed in a JWT payload,
  // which is only base64url-encoded (readable by anyone holding the token).
  const sensitiveKeys = Object.keys(payloadData).filter(k =>
    SENSITIVE_CLAIM_KEYS.includes(k.toLowerCase())
  );
  if (sensitiveKeys.length > 0) {
    findings.push({
      category: 'Claim',
      severity: 'warning',
      message: `Payload contains sensitive-looking claim(s): ${sensitiveKeys.join(', ')} (JWT payloads are not encrypted).`,
    });
    score -= 15;
  }

  return {
    score: Math.max(0, score),
    findings,
  };
}

/** Highest severity present in the findings, or null if there are none. */
export function highestSeverity(findings: Finding[]): Severity | null {
  if (findings.some(f => f.severity === 'critical')) return 'critical';
  if (findings.some(f => f.severity === 'warning')) return 'warning';
  if (findings.some(f => f.severity === 'info')) return 'info';
  return null;
}

export function generateConsoleReport(decoded: Jwt, analysis: Analysis): string {
  const { header, payload } = decoded;
  const payloadData = payload as JwtPayload;

  let output = chalk.bold.blue('\n--- JWT Analysis Report ---\n\n');
  output += chalk.bold.green('Header:\n') + JSON.stringify(header, null, 2) + '\n\n';
  output += chalk.bold.green('Payload:\n') + JSON.stringify(payload, null, 2) + '\n\n';

  const times: string[] = [];
  if (payloadData.iat !== undefined) times.push(`iat: ${formatTimestamp(payloadData.iat)}`);
  if (payloadData.nbf !== undefined) times.push(`nbf: ${formatTimestamp(payloadData.nbf)}`);
  if (payloadData.exp !== undefined) times.push(`exp: ${formatTimestamp(payloadData.exp)}`);
  if (times.length > 0) {
    output += chalk.bold.green('Timestamps:\n') + times.join('\n') + '\n\n';
  }

  output += chalk.bold.yellow('Security Analysis:\n');
  output += `Score: ${analysis.score}/100\n\n`;
  if (analysis.findings.length > 0) {
    output += chalk.bold('Findings:\n');
    analysis.findings.forEach(f => {
      const color = f.severity === 'critical' ? 'red' : f.severity === 'warning' ? 'yellow' : 'cyan';
      output += chalk[color](`[${f.severity.toUpperCase()}] ${f.category}: ${f.message}\n`);
    });
  } else {
    output += chalk.green('No issues found!\n');
  }
  return output;
}

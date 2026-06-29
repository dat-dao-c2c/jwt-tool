import type { Jwt, JwtPayload } from 'jsonwebtoken';

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

export function analyzeJwt(decoded: Jwt): Analysis {
  const { header, payload } = decoded;
  const findings: Finding[] = [];
  let score = 100;

  // Header Analysis
  if (header.crit) {
    findings.push({ category: 'Header', severity: 'critical', message: 'Contains "crit" header (potential attack vector).' });
    score -= 40;
  }
  
  if (header.alg === 'none') {
    findings.push({ category: 'Algorithm', severity: 'critical', message: 'Algorithm is set to "none".' });
    score -= 50;
  } else if (['HS256', 'HS384', 'HS512'].includes(header.alg as string)) {
    findings.push({ category: 'Algorithm', severity: 'warning', message: `Algorithm ${header.alg} used (ensure secret strength).` });
    score -= 10;
  }

  // Claim Analysis
  const payloadData = payload as JwtPayload;

  if (!payloadData.exp) {
    findings.push({ category: 'Claim', severity: 'critical', message: 'Missing "exp" (expiry) claim.' });
    score -= 30;
  } else if (payloadData.exp < Date.now() / 1000) {
    findings.push({ category: 'Claim', severity: 'critical', message: 'Token is expired.' });
    score -= 20;
  }

  if (!payloadData.iat) {
    findings.push({ category: 'Claim', severity: 'warning', message: 'Missing "iat" (issued at) claim.' });
    score -= 10;
  }

  if (!payloadData.jti) {
    findings.push({ category: 'Claim', severity: 'info', message: 'Missing "jti" (JWT ID) claim (recommended for replay protection).' });
    score -= 5;
  }

  return {
    score: Math.max(0, score),
    findings,
  };
}

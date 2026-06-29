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

export function generateConsoleReport(decoded: Jwt, analysis: Analysis): string {
  const { header, payload } = decoded;
  let output = chalk.bold.blue('\n--- JWT Analysis Report ---\n\n');
  output += chalk.bold.green('Header:\n') + JSON.stringify(header, null, 2) + '\n\n';
  output += chalk.bold.green('Payload:\n') + JSON.stringify(payload, null, 2) + '\n\n';
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

import { describe, it, expect } from 'vitest';
import { analyzeJwt, highestSeverity } from '../src/analyzer';
import type { Jwt } from 'jsonwebtoken';

function mk(header: any, payload: any): Jwt {
  return { header, payload, signature: 'abc' } as Jwt;
}

describe('analyzeJwt', () => {
  it('flags a minimal token with missing claims', () => {
    const analysis = analyzeJwt(mk({ alg: 'HS256' }, { sub: '123' }));
    expect(analysis.score).toBeLessThan(100);
    expect(analysis.findings.length).toBeGreaterThan(0);
  });

  it('marks alg "none" as critical', () => {
    const analysis = analyzeJwt(mk({ alg: 'none' }, {}));
    expect(analysis.findings.some(f => f.severity === 'critical' && f.category === 'Algorithm')).toBe(true);
  });

  it('detects an expired token', () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const analysis = analyzeJwt(mk({ alg: 'HS256' }, { exp: past }));
    expect(analysis.findings.some(f => f.message.includes('expired'))).toBe(true);
  });

  it('detects a not-yet-valid (nbf) token', () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const analysis = analyzeJwt(mk({ alg: 'HS256' }, { exp: future + 60, nbf: future }));
    expect(analysis.findings.some(f => f.message.includes('not yet valid'))).toBe(true);
  });

  it('does not fault a well-formed token beyond the HS256 warning', () => {
    const now = Math.floor(Date.now() / 1000);
    const analysis = analyzeJwt(
      mk({ alg: 'HS256', typ: 'JWT' }, { exp: now + 3600, iat: now, jti: 'x', iss: 'me', aud: 'you', sub: '1' })
    );
    expect(analysis.findings.every(f => f.severity !== 'critical')).toBe(true);
  });

  it('flags key-injection headers (jku/jwk/x5u/x5c) as critical', () => {
    for (const h of ['jku', 'jwk', 'x5u', 'x5c']) {
      const analysis = analyzeJwt(mk({ alg: 'RS256', [h]: 'x' }, {}));
      expect(
        analysis.findings.some(f => f.severity === 'critical' && f.message.includes(`"${h}"`))
      ).toBe(true);
    }
  });

  it('flags missing typ header', () => {
    const analysis = analyzeJwt(mk({ alg: 'RS256' }, {}));
    expect(analysis.findings.some(f => f.category === 'Header' && f.message.includes('typ'))).toBe(true);
  });

  it('rates missing iss/aud as warnings', () => {
    const analysis = analyzeJwt(mk({ alg: 'RS256', typ: 'JWT' }, {}));
    expect(analysis.findings.some(f => f.severity === 'warning' && f.message.includes('iss'))).toBe(true);
    expect(analysis.findings.some(f => f.severity === 'warning' && f.message.includes('aud'))).toBe(true);
  });

  it('flags a long-lived token', () => {
    const now = Math.floor(Date.now() / 1000);
    const analysis = analyzeJwt(mk({ alg: 'HS256' }, { iat: now, exp: now + 8 * 24 * 3600 }));
    expect(analysis.findings.some(f => f.message.includes('Long-lived'))).toBe(true);
  });

  it('flags sensitive claims in the payload', () => {
    const analysis = analyzeJwt(mk({ alg: 'HS256' }, { password: 'x', sub: '1' }));
    expect(analysis.findings.some(f => f.severity === 'warning' && f.message.includes('password'))).toBe(true);
  });
});

describe('highestSeverity', () => {
  it('returns null for no findings', () => {
    expect(highestSeverity([])).toBeNull();
  });

  it('picks critical over warning/info', () => {
    expect(
      highestSeverity([
        { category: 'Claim', severity: 'info', message: '' },
        { category: 'Algorithm', severity: 'critical', message: '' },
        { category: 'Claim', severity: 'warning', message: '' },
      ])
    ).toBe('critical');
  });
});

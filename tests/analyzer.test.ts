import { describe, it, expect } from 'vitest';
import { analyzeJwt } from '../src/analyzer';
import type { Jwt } from 'jsonwebtoken';

describe('analyzeJwt', () => {
  it('should analyze a token correctly', () => {
    const mockJwt: Jwt = {
      header: { alg: 'HS256' },
      payload: { sub: '123' },
      signature: 'abc'
    };

    const analysis = analyzeJwt(mockJwt);
    expect(analysis.score).toBeLessThan(100);
    expect(analysis.findings.length).toBeGreaterThan(0);
  });
});

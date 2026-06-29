import { describe, it, expect } from 'vitest';
import { generateSecret, evaluateSecret } from '../src/secret';

describe('secret utilities', () => {
  it('should generate a secret', () => {
    const secret = generateSecret(32);
    expect(secret.length).toBeGreaterThan(0);
  });

  it('should evaluate a weak secret', () => {
    const result = evaluateSecret('weak');
    expect(result.score).toBeLessThan(50);
  });
});

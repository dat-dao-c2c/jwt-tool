import { describe, it, expect } from 'vitest';
import { generateSecret, evaluateSecret, estimateEntropyBits } from '../src/secret';

describe('secret utilities', () => {
  it('should generate a secret', () => {
    const secret = generateSecret(32);
    expect(secret.length).toBeGreaterThan(0);
  });

  it('should evaluate a weak secret as low-scoring', () => {
    const result = evaluateSecret('weak');
    expect(result.score).toBeLessThan(50);
    expect(result.feedback.length).toBeGreaterThan(0);
  });

  it('should rate a generated 32-byte secret as strong', () => {
    // Regression: entropy-based scoring must not penalise a real random key
    // just because it lacks a symbol character.
    const secret = generateSecret(32);
    const result = evaluateSecret(secret);
    expect(result.score).toBe(100);
    expect(result.feedback).toEqual([]);
  });

  it('entropy grows with length', () => {
    expect(estimateEntropyBits('aaaaaaaaaaaaaaaa')).toBeLessThan(estimateEntropyBits(generateSecret(32)));
  });

  it('empty secret has zero entropy', () => {
    expect(estimateEntropyBits('')).toBe(0);
  });
});

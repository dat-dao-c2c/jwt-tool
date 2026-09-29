import crypto from 'crypto';

export function generateSecret(length: number = 64): string {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Estimate the character set size a secret appears to be drawn from.
 * Used to approximate brute-force resistance rather than enforcing
 * arbitrary "must contain a symbol" rules that penalise strong random keys.
 */
function estimatedCharsetSize(secret: string): number {
  let size = 0;
  if (/[a-z]/.test(secret)) size += 26;
  if (/[A-Z]/.test(secret)) size += 26;
  if (/[0-9]/.test(secret)) size += 10;
  if (/[-_]/.test(secret)) size += 2; // base64url symbols
  if (/[^A-Za-z0-9\-_]/.test(secret)) size += 32; // other punctuation/symbols
  return size || 1;
}

/**
 * Estimate secret strength in bits of entropy: length * log2(charset).
 * This treats a long random base64url key (the output of generateSecret)
 * as strong, which character-class heuristics wrongly flag as weak.
 */
export function estimateEntropyBits(secret: string): number {
  if (secret.length === 0) return 0;
  return secret.length * Math.log2(estimatedCharsetSize(secret));
}

export function evaluateSecret(secret: string): { score: number; entropyBits: number; feedback: string[] } {
  const feedback: string[] = [];
  const entropyBits = estimateEntropyBits(secret);

  // Map entropy to a 0-100 score. 128 bits is treated as full strength,
  // which is the common floor for HMAC signing keys.
  const score = Math.max(0, Math.min(100, Math.round((entropyBits / 128) * 100)));

  if (secret.length < 16) {
    feedback.push('Secret is too short (critical risk); use at least 32 characters.');
  } else if (secret.length < 32) {
    feedback.push('Secret is a bit short; consider at least 32 characters.');
  }

  if (entropyBits < 80) {
    feedback.push(`Low entropy (~${Math.round(entropyBits)} bits); aim for 128+ bits (e.g. use generate-secret).`);
  } else if (entropyBits < 128) {
    feedback.push(`Moderate entropy (~${Math.round(entropyBits)} bits); 128+ bits is recommended.`);
  }

  return { score, entropyBits, feedback };
}

import crypto from 'crypto';

export function generateSecret(length: number = 64): string {
  return crypto.randomBytes(length).toString('base64url');
}

export function evaluateSecret(secret: string): { score: number; feedback: string[] } {
  let score = 0;
  const feedback: string[] = [];

  // Length check
  if (secret.length >= 32) {
    score += 40;
  } else if (secret.length >= 16) {
    score += 20;
    feedback.push('Secret is a bit short, consider increasing length.');
  } else {
    feedback.push('Secret is too short (critical risk).');
  }

  // Complexity check
  const hasUpper = /[A-Z]/.test(secret);
  const hasLower = /[a-z]/.test(secret);
  const hasNumber = /[0-9]/.test(secret);
  const hasSpecial = /[^A-Za-z0-9]/.test(secret);

  if (hasUpper && hasLower && hasNumber && hasSpecial) {
    score += 60;
  } else {
    feedback.push('Secret lacks complexity (use uppercase, lowercase, numbers, and special characters).');
  }

  return { score, feedback };
}

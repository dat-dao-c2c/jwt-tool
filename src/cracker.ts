import jwt, { type Algorithm } from 'jsonwebtoken';
import fs from 'fs';
import readline from 'readline';

const HMAC_ALGS: Algorithm[] = ['HS256', 'HS384', 'HS512'];

export interface CrackResult {
  secret: string | null;
  attempts: number;
}

export interface CrackOptions {
  /** Called periodically with the number of secrets tried so far. */
  onProgress?: (attempts: number) => void;
  /** Emit progress every N attempts (default 50_000). */
  progressInterval?: number;
}

/** Read the alg from a token header without verifying it. */
export function getTokenAlgorithm(token: string): string | undefined {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === 'string') return undefined;
  return decoded.header.alg;
}

export async function crackJwt(
  token: string,
  wordlistPath: string,
  options: CrackOptions = {}
): Promise<CrackResult> {
  const alg = getTokenAlgorithm(token);
  if (!alg || !HMAC_ALGS.includes(alg as Algorithm)) {
    throw new Error(
      `Token algorithm "${alg ?? 'unknown'}" is not a symmetric HMAC algorithm; ` +
        `wordlist cracking only applies to ${HMAC_ALGS.join(', ')}.`
    );
  }

  if (!fs.existsSync(wordlistPath)) {
    throw new Error(`Wordlist file not found: ${wordlistPath}`);
  }

  const algorithms = [alg as Algorithm];
  const progressInterval = options.progressInterval ?? 50_000;

  const fileStream = fs.createReadStream(wordlistPath);
  const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

  let attempts = 0;
  try {
    for await (const secret of rl) {
      attempts++;
      try {
        // Pin algorithms to the token's HMAC alg to avoid confusion attacks.
        jwt.verify(token, secret, { algorithms });
        return { secret, attempts };
      } catch {
        // Wrong secret; keep going.
      }
      if (options.onProgress && attempts % progressInterval === 0) {
        options.onProgress(attempts);
      }
    }
  } finally {
    rl.close();
    fileStream.destroy();
  }

  return { secret: null, attempts };
}

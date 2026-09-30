import jwt, { type Algorithm } from 'jsonwebtoken';
import fs from 'fs';
import readline from 'readline';
import { Readable } from 'stream';

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

interface WordlistStream {
  stream: NodeJS.ReadableStream;
  /** Whether crackJwt owns the stream and should destroy it when done. */
  cleanup: () => void;
}

/**
 * Open a wordlist from a file path, an http(s) URL, or "-" (stdin).
 * Returns the readable stream plus a cleanup function.
 */
async function openWordlist(source: string): Promise<WordlistStream> {
  if (source === '-') {
    // Do not destroy the shared process.stdin; readline closing is enough.
    return { stream: process.stdin, cleanup: () => {} };
  }

  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source);
    if (!res.ok) {
      throw new Error(`Failed to fetch wordlist: HTTP ${res.status} ${res.statusText}`);
    }
    if (!res.body) {
      throw new Error('Failed to fetch wordlist: empty response body');
    }
    const stream = Readable.fromWeb(res.body as any);
    return { stream, cleanup: () => stream.destroy() };
  }

  if (!fs.existsSync(source)) {
    throw new Error(`Wordlist file not found: ${source}`);
  }
  const stream = fs.createReadStream(source);
  return { stream, cleanup: () => stream.destroy() };
}

/**
 * Brute-force an HMAC JWT secret against a wordlist.
 * @param source A file path, an http(s):// URL, or "-" for stdin.
 */
export async function crackJwt(
  token: string,
  source: string,
  options: CrackOptions = {}
): Promise<CrackResult> {
  const alg = getTokenAlgorithm(token);
  if (!alg || !HMAC_ALGS.includes(alg as Algorithm)) {
    throw new Error(
      `Token algorithm "${alg ?? 'unknown'}" is not a symmetric HMAC algorithm; ` +
        `wordlist cracking only applies to ${HMAC_ALGS.join(', ')}.`
    );
  }

  const algorithms = [alg as Algorithm];
  const progressInterval = options.progressInterval ?? 50_000;

  const { stream, cleanup } = await openWordlist(source);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

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
    cleanup();
  }

  return { secret: null, attempts };
}

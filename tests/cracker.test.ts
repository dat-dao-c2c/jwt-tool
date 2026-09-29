import { describe, it, expect, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import jwt from 'jsonwebtoken';
import { crackJwt, getTokenAlgorithm } from '../src/cracker';

const tmpFiles: string[] = [];

function writeWordlist(lines: string[]): string {
  const p = path.join(os.tmpdir(), `wl-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`);
  fs.writeFileSync(p, lines.join('\n'));
  tmpFiles.push(p);
  return p;
}

afterAll(() => {
  for (const f of tmpFiles) fs.rmSync(f, { force: true });
});

describe('getTokenAlgorithm', () => {
  it('reads the alg from the header', () => {
    const token = jwt.sign({ sub: '1' }, 'secret', { algorithm: 'HS256' });
    expect(getTokenAlgorithm(token)).toBe('HS256');
  });
});

describe('crackJwt', () => {
  it('finds a secret present in the wordlist', async () => {
    const token = jwt.sign({ sub: '1' }, 's3cr3t', { algorithm: 'HS256' });
    const wl = writeWordlist(['wrong', 's3cr3t', 'other']);
    const result = await crackJwt(token, wl);
    expect(result.secret).toBe('s3cr3t');
    expect(result.attempts).toBe(2);
  });

  it('returns null when the secret is absent', async () => {
    const token = jwt.sign({ sub: '1' }, 'realsecret', { algorithm: 'HS256' });
    const wl = writeWordlist(['a', 'b', 'c']);
    const result = await crackJwt(token, wl);
    expect(result.secret).toBeNull();
    expect(result.attempts).toBe(3);
  });

  it('rejects non-HMAC tokens', async () => {
    // alg:none token — decodable but not HMAC.
    const token = jwt.sign({ sub: '1' }, '', { algorithm: 'none' });
    const wl = writeWordlist(['x']);
    await expect(crackJwt(token, wl)).rejects.toThrow(/not a symmetric HMAC/);
  });

  it('errors on a missing wordlist file', async () => {
    const token = jwt.sign({ sub: '1' }, 's', { algorithm: 'HS256' });
    await expect(crackJwt(token, '/no/such/file.list')).rejects.toThrow(/not found/);
  });
});

import fs from 'fs';
import { Command } from 'commander';
import jwt, { type Jwt, type Algorithm } from 'jsonwebtoken';
import chalk from 'chalk';
import pkg from '../package.json';
import { analyzeJwt, generateConsoleReport, highestSeverity, type Severity } from './analyzer.js';
import { crackJwt, getTokenAlgorithm } from './cracker.js';
import { generateSecret, evaluateSecret } from './secret.js';

const program = new Command();

/**
 * Resolve a CLI argument that may be inline, "@path" (read from file),
 * or "-" (read from stdin). Trims a single trailing newline.
 */
function resolveInput(value: string): string {
  if (value === '-') {
    return fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
  }
  if (value.startsWith('@')) {
    return fs.readFileSync(value.slice(1), 'utf8').replace(/\r?\n$/, '');
  }
  return value;
}

/** Severity rank for --fail-on gating (higher = more severe). */
const SEVERITY_RANK: Record<Severity, number> = { info: 1, warning: 2, critical: 3 };

function decodeOrExit(token: string): Jwt {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === 'string') {
    console.error('Error: Could not decode token');
    process.exit(1);
  }
  return decoded as Jwt;
}

program
  .name('jwt-tool')
  .description('A CLI tool to decode, analyze, and crack HS256 JSON Web Tokens (JWTs).')
  .version(pkg.version);

program
  .command('decode')
  .description('Decode a JWT')
  .argument('<token>', 'The JWT to decode (or "@file" / "-" for stdin)')
  .option('-r, --report [type]', 'Generate console report')
  .action((token: string, options: { report?: string | boolean }) => {
    try {
      const decoded = decodeOrExit(resolveInput(token));
      const analysis = analyzeJwt(decoded);

      if (options.report) {
        console.log(generateConsoleReport(decoded, analysis));
      } else {
        console.log(JSON.stringify({ ...decoded, analysis }, null, 2));
      }
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('analyze')
  .description('Analyze a JWT for security issues')
  .argument('<token>', 'The JWT to analyze (or "@file" / "-" for stdin)')
  .option('--fail-on <severity>', 'Exit non-zero if a finding at or above this severity is present (critical|warning|info)')
  .action((token: string, options: { failOn?: string }) => {
    try {
      const decoded = decodeOrExit(resolveInput(token));
      const analysis = analyzeJwt(decoded);
      console.log(JSON.stringify(analysis, null, 2));

      if (options.failOn) {
        const threshold = options.failOn.toLowerCase() as Severity;
        if (!(threshold in SEVERITY_RANK)) {
          console.error(`Error: --fail-on must be one of: critical, warning, info`);
          process.exit(1);
        }
        const worst = highestSeverity(analysis.findings);
        if (worst && SEVERITY_RANK[worst] >= SEVERITY_RANK[threshold]) {
          process.exit(2);
        }
      }
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('verify')
  .description('Verify a JWT signature')
  .argument('<token>', 'The JWT to verify (or "@file" / "-" for stdin)')
  .argument('[secret]', 'The secret or public key (or "@file")')
  .option('-k, --key-file <path>', 'Read the secret / public key from a file')
  .option('-a, --alg <alg...>', 'Allowed algorithm(s) to accept (defaults to the token\'s alg)')
  .action((token: string, secret: string | undefined, options: { keyFile?: string; alg?: string[] }) => {
    try {
      const resolvedToken = resolveInput(token);
      let key: string;
      if (options.keyFile) {
        key = fs.readFileSync(options.keyFile, 'utf8');
      } else if (secret !== undefined) {
        key = resolveInput(secret);
      } else {
        console.error('Error: provide a <secret> argument or --key-file');
        process.exit(1);
      }

      // Pin algorithms to prevent algorithm-confusion attacks. Default to the
      // token's own alg rather than letting the library infer a permissive set.
      const algorithms = (options.alg ?? [getTokenAlgorithm(resolvedToken)].filter(Boolean)) as Algorithm[];
      const decoded = jwt.verify(resolvedToken, key, algorithms.length ? { algorithms } : undefined);
      console.log(JSON.stringify({ valid: true, payload: decoded }, null, 2));
    } catch (err: any) {
      console.log(JSON.stringify({ valid: false, error: err.message }, null, 2));
      process.exit(1);
    }
  });

program
  .command('generate')
  .description('Generate a new JWT')
  .argument('<payloadJSON>', 'JSON string for payload (or "@file")')
  .argument('[secret]', 'Secret / private key to sign with (or "@file")')
  .option('-a, --alg <alg>', 'Algorithm (e.g., HS256, RS256)', 'HS256')
  .option('-k, --key-file <path>', 'Read the signing secret / private key from a file')
  .option('-e, --expires-in <duration>', 'Set expiry (e.g. 3600, "1h", "7d")')
  .action((payloadJSON: string, secret: string | undefined, options: { alg: string; keyFile?: string; expiresIn?: string }) => {
    try {
      const payload = JSON.parse(resolveInput(payloadJSON));
      let key: string;
      if (options.keyFile) {
        key = fs.readFileSync(options.keyFile, 'utf8');
      } else if (secret !== undefined) {
        key = resolveInput(secret);
      } else {
        console.error('Error: provide a <secret> argument or --key-file');
        process.exit(1);
      }

      const signOptions: jwt.SignOptions = { algorithm: options.alg as Algorithm };
      if (options.expiresIn) {
        const asNumber = Number(options.expiresIn);
        signOptions.expiresIn = Number.isNaN(asNumber) ? (options.expiresIn as any) : asNumber;
      }
      const token = jwt.sign(payload, key, signOptions);
      console.log(token);
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('crack')
  .description('Brute-force HS256 JWT secret using a wordlist')
  .argument('<token>', 'The JWT to crack (or "@file" / "-" for stdin)')
  .argument('<wordlist>', 'Wordlist source: a file path, an http(s):// URL, or "-" for stdin')
  .action(async (token: string, wordlist: string) => {
    try {
      const resolvedToken = resolveInput(token);
      console.log('Attempting to crack secret...');
      const { secret, attempts } = await crackJwt(resolvedToken, wordlist, {
        onProgress: (n) => process.stderr.write(`\r  tried ${n.toLocaleString()} candidates...`),
      });
      process.stderr.write('\r');
      if (secret) {
        console.log(chalk.bold.green(`Success! Found secret after ${attempts.toLocaleString()} attempts: ${secret}`));
      } else {
        console.log(chalk.bold.red(`Could not find secret in wordlist (${attempts.toLocaleString()} candidates tried).`));
        process.exit(1);
      }
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('generate-secret')
  .description('Generate a cryptographically strong random secret')
  .option('-l, --length <length>', 'Length in bytes', '64')
  .action((options: { length: string }) => {
    const secret = generateSecret(parseInt(options.length, 10));
    console.log(secret);
  });

program
  .command('evaluate-secret')
  .description('Evaluate the strength of a secret key')
  .argument('<secret>', 'The secret to evaluate (or "@file")')
  .action((secret: string) => {
    const { score, entropyBits, feedback } = evaluateSecret(resolveInput(secret));
    console.log(`Score: ${score}/100 (~${Math.round(entropyBits)} bits of entropy)`);
    if (feedback.length > 0) {
      console.log('Feedback:', feedback.join(' '));
    } else {
      console.log('Secret is strong!');
    }
  });

program.parse();

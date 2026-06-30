import { Command } from 'commander';
import jwt, { type Jwt } from 'jsonwebtoken';
import chalk from 'chalk';
import { analyzeJwt, generateConsoleReport } from './analyzer.js';
import { crackJwt } from './cracker.js';
import { generateSecret, evaluateSecret } from './secret.js';

const program = new Command();

program
  .name('jwt-tool')
  .description('A CLI tool to decode, analyze, and crack HS256 JSON Web Tokens (JWTs).')
  .version('1.0.0');

program
  .command('decode')
  .description('Decode a JWT')
  .argument('<token>', 'The JWT to decode')
  .option('-r, --report [type]', 'Generate console report')
  .action((token: string, options: { report?: string | boolean }) => {
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        console.error('Error: Could not decode token');
        process.exit(1);
      }
      
      const analysis = analyzeJwt(decoded as Jwt);
      
      // If flag is present (either --report or --report console)
      if (options.report) {
        console.log(generateConsoleReport(decoded as Jwt, analysis));
      } else {
        console.log(JSON.stringify({ 
          ...decoded,
          analysis
        }, null, 2));
      }
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('analyze')
  .description('Analyze a JWT for security issues')
  .argument('<token>', 'The JWT to analyze')
  .action((token: string) => {
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        console.error('Error: Could not decode token');
        process.exit(1);
      }
      
      const analysis = analyzeJwt(decoded as Jwt);
      
      console.log(JSON.stringify(analysis, null, 2));
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('verify')
  .description('Verify a JWT signature')
  .argument('<token>', 'The JWT to verify')
  .argument('<secret>', 'The secret or public key')
  .action((token: string, secret: string) => {
    try {
      const decoded = jwt.verify(token, secret);
      console.log(JSON.stringify({ valid: true, payload: decoded }, null, 2));
    } catch (err: any) {
      console.log(JSON.stringify({ valid: false, error: err.message }, null, 2));
      process.exit(1);
    }
  });

program
  .command('generate')
  .description('Generate a new JWT')
  .argument('<payloadJSON>', 'JSON string for payload')
  .argument('<secret>', 'Secret to sign with')
  .option('-a, --alg <alg>', 'Algorithm (e.g., HS256, RS256)', 'HS256')
  .action((payloadJSON: string, secret: string, options: { alg: string }) => {
    try {
      const payload = JSON.parse(payloadJSON);
      const token = jwt.sign(payload, secret, { algorithm: options.alg as any });
      console.log(token);
    } catch (err: any) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program
  .command('crack')
  .description('Brute-force HS256 JWT secret using a wordlist')
  .argument('<token>', 'The JWT to crack')
  .argument('<wordlist>', 'Path to the wordlist file')
  .action(async (token: string, wordlist: string) => {
    try {
      console.log('Attempting to crack secret...');
      const secret = await crackJwt(token, wordlist);
      if (secret) {
        console.log(chalk.bold.green(`Success! Found secret: ${secret}`));
      } else {
        console.log(chalk.bold.red('Could not find secret in wordlist.'));
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
  .argument('<secret>', 'The secret to evaluate')
  .action((secret: string) => {
    const { score, feedback } = evaluateSecret(secret);
    console.log(`Score: ${score}/100`);
    if (feedback.length > 0) {
      console.log('Feedback:', feedback.join(' '));
    } else {
      console.log('Secret is strong!');
    }
  });

program.parse();

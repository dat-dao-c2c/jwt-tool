import { Command } from 'commander';
import jwt from 'jsonwebtoken';
import { analyzeJwt } from './analyzer.js';

const program = new Command();

program
  .name('jwt-tool')
  .description('A CLI tool to decode and inspect JWTs')
  .version('1.0.0');

program
  .command('decode')
  .description('Decode a JWT')
  .argument('<token>', 'The JWT to decode')
  .action((token: string) => {
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        console.error('Error: Could not decode token');
        process.exit(1);
      }
      
      const analysis = analyzeJwt(decoded);
      
      console.log(JSON.stringify({ 
        ...decoded,
        analysis
      }, null, 2));
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
      
      const analysis = analyzeJwt(decoded);
      
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

program.parse();

import jwt from 'jsonwebtoken';
import fs from 'fs';
import readline from 'readline';

export async function crackJwt(token: string, wordlistPath: string): Promise<string | null> {
  const fileStream = fs.createReadStream(wordlistPath);

  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  for await (const secret of rl) {
    try {
      jwt.verify(token, secret);
      // If no error, secret is found
      rl.close();
      fileStream.destroy();
      return secret;
    } catch (err) {
      // Continue to next secret
      continue;
    }
  }

  return null;
}

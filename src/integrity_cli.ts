import { readFileSync } from 'node:fs';
import { canonicalizeEvent, sha256 } from './integrity.ts';

async function main(): Promise<void> {
  const input = await new Promise<string>((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (part: string) => { data += part; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
  try {
    const parsed: unknown = JSON.parse(input);
    const result = canonicalizeEvent(parsed);
    process.stdout.write(JSON.stringify({
      event: result.event,
      canonicalEventBase64: result.bytes.toString('base64'),
      canonicalEventSha256: sha256(result.bytes).toString('hex'),
    }));
  } catch (error) {
    process.stderr.write(error instanceof Error ? error.message : 'Invalid event');
    process.exitCode = 2;
  }
}

if (process.argv[2] === '--sha256-file') {
  try {
    if (!process.argv[3] || process.argv.length !== 4) throw new Error('expected one evidence file path');
    process.stdout.write(sha256(readFileSync(process.argv[3])).toString('hex'));
  } catch (error) {
    process.stderr.write(error instanceof Error ? error.message : 'Unable to hash evidence');
    process.exitCode = 2;
  }
} else {
  await main();
}

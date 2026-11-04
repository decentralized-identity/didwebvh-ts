import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { EXAMPLE_DIR, generateExampleFiles } from '../scripts/generate-examples.js';
import type { DIDLog, WitnessProofFileEntry } from '../src/interfaces.js';
import { resolveDIDFromLog } from '../src/method.js';

const readExample = (name: string) => readFileSync(join(EXAMPLE_DIR, name), 'utf8');

describe('example DID files', () => {
  test('the committed example log resolves with its witness proofs', async () => {
    const log = readExample('did.jsonl')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line)) as DIDLog;
    const witnessProofs = JSON.parse(readExample('did-witness.json')) as WitnessProofFileEntry[];

    const resolved = await resolveDIDFromLog(log, { witnessProofs });

    expect(resolved.didResolutionMetadata.error).toBeUndefined();
    expect(resolved.didDocument?.id).toBe(log[0].state.id);
    expect(JSON.parse(readExample('did.json')).alsoKnownAs).toContain(log[0].state.id);
  });

  test('the generator reproduces the committed example files', async () => {
    const files = await generateExampleFiles();

    expect(Object.keys(files).sort()).toEqual(['did-witness.json', 'did.json', 'did.jsonl']);
    for (const [name, content] of Object.entries(files)) {
      expect(content, name).toBe(readExample(name));
    }
  });
});

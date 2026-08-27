import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { globSync } from 'glob';
import { describe, expect, test } from 'vitest';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

describe('runtime and CLI package boundary', () => {
  test('runtime source has no CLI or ambient Node dependencies', () => {
    const runtimeFiles = globSync('src/**/*.ts', {
      cwd: repositoryRoot,
      ignore: ['src/cli/**'],
      absolute: true,
    });

    for (const file of runtimeFiles) {
      const source = readFileSync(file, 'utf8');
      expect(source).not.toMatch(/(?:from|import\()\s*['"][^'"]*\/cli(?:\/|['"])/);
      expect(source).not.toMatch(/node:(?:fs|path|process)/);
      expect(source).not.toContain('process.env');
      expect(source).not.toMatch(/from\s*['"]dotenv['"]/);
    }
  });

  test('runtime ESM bundle excludes CLI and environment handling', async () => {
    const result = await build({
      entryPoints: [new URL('../src/index.ts', import.meta.url).pathname],
      bundle: true,
      format: 'esm',
      platform: 'browser',
      write: false,
      minify: true,
      define: {
        'process.env.NODE_ENV': '"production"',
        global: 'globalThis',
      },
    });
    const output = result.outputFiles?.[0]?.text ?? '';

    expect(output).not.toContain('DID_VERIFICATION_METHODS');
    expect(output).not.toContain('process.argv');
    expect(output).not.toContain('node:fs');
    expect(output).not.toContain('node:path');
  });

  test('CLI bundle remains an independent entry point', async () => {
    const result = await build({
      entryPoints: [new URL('../src/cli/index.ts', import.meta.url).pathname],
      bundle: true,
      format: 'esm',
      platform: 'node',
      write: false,
    });
    const output = result.outputFiles?.[0]?.text ?? '';

    expect(output).toContain('DID_VERIFICATION_METHODS');
    expect(output).toContain('process.argv');
  });
});

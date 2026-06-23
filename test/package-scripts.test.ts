import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import pkg from '../package.json';

describe('package scripts', () => {
  test('dev starts the resolver without waiting for a debugger', () => {
    expect(pkg.scripts.dev).toBe('bun --watch ./examples/elysia-resolver.ts');
    expect(pkg.scripts.dev).not.toContain('--inspect');
  });

  test('debug mode is available as an explicit script', () => {
    expect(pkg.scripts.debug).toBe('bun --watch --inspect ./examples/elysia-resolver.ts');
  });

  test('resolver example port can be configured with PORT', () => {
    const resolverSource = readFileSync(new URL('../examples/elysia-resolver.ts', import.meta.url), 'utf-8');

    expect(resolverSource).toContain('process.env.PORT');
    expect(resolverSource).not.toContain('const port = 3010');
  });

  test('dev resolver imports local source from a source checkout', () => {
    const resolverSource = readFileSync(new URL('../examples/elysia-resolver.ts', import.meta.url), 'utf-8');

    expect(resolverSource).not.toContain("from 'didwebvh-ts'");
    expect(resolverSource).not.toContain("from 'didwebvh-ts/types'");
  });
});

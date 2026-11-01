import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { globSync } from 'glob';
import { describe, expect, test } from 'vitest';
import { reactNativeIdnaPlugin } from '../scripts/react-native-idna-plugin.js';
import { createUncanonicalisedDID } from './utils.js';

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
    expect(output).not.toContain('setDomainToASCII');
  });

  test('opt-in React Native bundle uses the supplied converter without affecting the default bundle', async () => {
    const [standardBuild, reactNativeBuild] = await Promise.all(
      ['src/index.ts', 'src/react-native/index.ts'].map((entry, index) =>
        build({
          entryPoints: [new URL(`../${entry}`, import.meta.url).pathname],
          bundle: true,
          format: 'esm',
          platform: 'browser',
          write: false,
          plugins: index === 1 ? [reactNativeIdnaPlugin] : [],
        })
      )
    );
    const standardSource = standardBuild.outputFiles?.[0]?.text;
    const reactNativeSource = reactNativeBuild.outputFiles?.[0]?.text;
    expect(standardSource).toBeDefined();
    expect(reactNativeSource).toBeDefined();
    expect(standardSource).not.toContain('setDomainToASCII');
    expect(reactNativeSource).toContain('setDomainToASCII');
    expect(reactNativeSource).not.toContain('tr46');

    const standard = await import(`data:text/javascript;base64,${Buffer.from(standardSource!).toString('base64')}`);
    const reactNative = await import(
      `data:text/javascript;base64,${Buffer.from(reactNativeSource!).toString('base64')}`
    );
    const { created, verifier } = await createUncanonicalisedDID({
      did: 'did:webvh:{SCID}:b%C3%BCcher.example.com',
    });
    const NativeURL = URL;
    const originalURL = globalThis.URL;
    globalThis.URL = class extends NativeURL {
      override get hostname() {
        return super.hostname.replace(/^xn--/, '');
      }
    };
    try {
      expect((await standard.resolveDIDFromLog(created.log, { verifier })).didResolutionMetadata.error).toBe(
        'internalError'
      );
      expect((await reactNative.resolveDIDFromLog(created.log, { verifier })).didResolutionMetadata.error).toBe(
        'internalError'
      );
      reactNative.setDomainToASCII((host: string) => new NativeURL(`https://${host}`).hostname);
      expect((await reactNative.resolveDIDFromLog(created.log, { verifier })).didDocument?.id).toBe(created.did);
      expect((await standard.resolveDIDFromLog(created.log, { verifier })).didResolutionMetadata.error).toBe(
        'internalError'
      );
      reactNative.setDomainToASCII(() => 'not a valid host');
      expect((await reactNative.resolveDIDFromLog(created.log, { verifier })).didResolutionMetadata.error).toBe(
        'invalidDid'
      );
    } finally {
      reactNative.setDomainToASCII(undefined);
      globalThis.URL = originalURL;
    }
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

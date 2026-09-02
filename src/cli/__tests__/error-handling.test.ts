import fs from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, test, vi } from 'vitest';
import { CliError, handleCreate, handleDeactivate, handleResolve, handleUpdate, main } from '../index';

const TEST_DIR = join(process.cwd(), 'test', 'temp-cli-error-handling');
fs.mkdirSync(TEST_DIR, { recursive: true });

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
});

describe('CLI error handling', () => {
  test('handlers reject missing required arguments without exiting', async () => {
    await expect(handleCreate([])).rejects.toMatchObject({
      name: 'CliError',
      message: 'Address is required for create command (use --address)',
    });
    await expect(handleResolve([])).rejects.toMatchObject({
      name: 'CliError',
      message: 'Either --did or --log is required for resolve command',
    });
    await expect(handleUpdate([])).rejects.toMatchObject({
      name: 'CliError',
      message: 'Log file is required for update command',
    });
    await expect(handleDeactivate([])).rejects.toMatchObject({
      name: 'CliError',
      message: 'Log file is required for deactivate command',
    });
  });

  test('main returns an exit code instead of terminating for an unknown command', async () => {
    const originalArgv = process.argv;
    process.argv = [...originalArgv.slice(0, 2), 'unknown'];

    try {
      await expect(main()).resolves.toBe(1);
    } finally {
      process.argv = originalArgv;
    }
  });

  test('CLI errors expose their exit code', () => {
    expect(new CliError('invalid command', 2).exitCode).toBe(2);
  });

  describe('unknown command output', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    test('main prints usage before reporting an unknown command', async () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const originalArgv = process.argv;
      process.argv = [...originalArgv.slice(0, 2), 'unknown'];

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Usage:'));
        expect(errorSpy).toHaveBeenCalledWith('Unknown command: unknown');
      } finally {
        process.argv = originalArgv;
      }
    });
  });

  describe('top-level error reporting', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    test('prints only the message for a CliError', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const originalArgv = process.argv;
      process.argv = [...originalArgv.slice(0, 2), 'resolve'];

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledTimes(1);
        expect(errorSpy).toHaveBeenCalledWith('Either --did or --log is required for resolve command');
      } finally {
        process.argv = originalArgv;
      }
    });

    test('prints the stack trace for an unexpected, non-CliError error', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const originalArgv = process.argv;
      process.argv = [
        ...originalArgv.slice(0, 2),
        'generate-witness-proof',
        '--version-id',
        '1-abc',
        '--witness-did',
        'did:key:invalid',
        '--witness-secret',
        'zBAD',
        '--output',
        '/tmp/cli-error-handling-test-witness.json',
      ];

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledTimes(1);
        const loggedValue = errorSpy.mock.calls[0][0];
        expect(loggedValue).toEqual(expect.stringContaining('Error:'));
        expect(loggedValue).toEqual(expect.stringContaining(' at '));
      } finally {
        process.argv = originalArgv;
      }
    });
  });

  describe('resolve/update/deactivate surface the original CliError unwrapped', () => {
    test('handleResolve propagates the inner resolution CliError without re-wrapping', async () => {
      const logFile = join(TEST_DIR, 'bad-resolve.jsonl');
      fs.writeFileSync(logFile, `${JSON.stringify({ invalid: 'log' })}\n`);

      await expect(handleResolve(['--log', logFile])).rejects.toMatchObject({
        name: 'CliError',
        message: expect.stringContaining('Resolution error:'),
      });
      // Guards against the double-wrap regression: message must not contain the
      // outer "Error resolving DID:" prefix that would appear if re-wrapped.
      await expect(handleResolve(['--log', logFile])).rejects.not.toMatchObject({
        message: expect.stringContaining('Error resolving DID:'),
      });
    });

    test('handleResolve wraps unexpected non-CliError errors with context', async () => {
      const missingFile = join(TEST_DIR, 'does-not-exist.jsonl');

      await expect(handleResolve(['--log', missingFile])).rejects.toMatchObject({
        name: 'CliError',
        message: expect.stringContaining('Error resolving DID:'),
      });
    });

    test('handleUpdate wraps unexpected errors reading a missing log file', async () => {
      const missingFile = join(TEST_DIR, 'does-not-exist-update.jsonl');

      await expect(handleUpdate(['--log', missingFile])).rejects.toMatchObject({
        name: 'CliError',
        message: expect.stringContaining('Error updating DID:'),
      });
    });

    test('handleDeactivate wraps unexpected errors reading a missing log file', async () => {
      const missingFile = join(TEST_DIR, 'does-not-exist-deactivate.jsonl');

      await expect(handleDeactivate(['--log', missingFile])).rejects.toMatchObject({
        name: 'CliError',
        message: expect.stringContaining('Error deactivating DID:'),
      });
    });
  });

  describe('generate-witness-proof argument validation', () => {
    test('rejects when no --version-id is provided', async () => {
      const originalArgv = process.argv;
      process.argv = [
        ...originalArgv.slice(0, 2),
        'generate-witness-proof',
        '--witness-did',
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        '--witness-secret',
        'z1A',
        '--output',
        join(TEST_DIR, 'witness.json'),
      ];
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledWith('At least one --version-id is required');
      } finally {
        process.argv = originalArgv;
        errorSpy.mockRestore();
      }
    });

    test('rejects when --output is missing', async () => {
      const originalArgv = process.argv;
      process.argv = [
        ...originalArgv.slice(0, 2),
        'generate-witness-proof',
        '--version-id',
        '1-abc',
        '--witness-did',
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        '--witness-secret',
        'z1A',
      ];
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledWith('Output file is required');
      } finally {
        process.argv = originalArgv;
        errorSpy.mockRestore();
      }
    });

    test('rejects when witness DIDs and secrets counts do not match', async () => {
      const originalArgv = process.argv;
      process.argv = [
        ...originalArgv.slice(0, 2),
        'generate-witness-proof',
        '--version-id',
        '1-abc',
        '--witness-did',
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        '--witness-did',
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        '--witness-secret',
        'z1A',
        '--output',
        join(TEST_DIR, 'witness.json'),
      ];
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledWith('Must provide matching number of witness DIDs and secrets');
      } finally {
        process.argv = originalArgv;
        errorSpy.mockRestore();
      }
    });
  });

  describe('--add-vm argument validation', () => {
    test('rejects an invalid verification method type', async () => {
      const originalArgv = process.argv;
      process.argv = [
        ...originalArgv.slice(0, 2),
        'update',
        '--log',
        join(TEST_DIR, 'does-not-matter.jsonl'),
        '--add-vm',
        'not-a-real-type',
      ];
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        const exitCode = await main();
        expect(exitCode).toBe(1);
        expect(errorSpy).toHaveBeenCalledWith('Invalid verification method type: not-a-real-type');
      } finally {
        process.argv = originalArgv;
        errorSpy.mockRestore();
      }
    });
  });

  describe('handleDeactivate environment failures', () => {
    const ENV_FILE = join(process.cwd(), '.env');

    test('wraps "no verification method found in environment" as a CliError', async () => {
      const logFile = join(TEST_DIR, 'deactivate-no-env.jsonl');
      const originalEnvVar = process.env.DID_VERIFICATION_METHODS;
      let originalEnvFile: string | null = null;
      try {
        originalEnvFile = fs.readFileSync(ENV_FILE, 'utf8');
      } catch {
        originalEnvFile = null;
      }

      try {
        // Create a minimal DID via handleCreate without --output, so no env VM is persisted,
        // but capture the log for use with handleDeactivate against a clean environment.
        const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        const created = await handleCreate(['--address', 'example.com', '--portable']);
        logSpy.mockRestore();
        fs.writeFileSync(logFile, `${created.log.map((entry) => JSON.stringify(entry)).join('\n')}\n`);

        // Ensure both the in-process env var and the on-disk .env fallback are clear,
        // since getVerificationMethodsFromEnv() reads whichever is present.
        delete process.env.DID_VERIFICATION_METHODS;
        fs.writeFileSync(ENV_FILE, '');

        await expect(handleDeactivate(['--log', logFile])).rejects.toMatchObject({
          name: 'CliError',
          message: expect.stringContaining('No verification method found in environment'),
        });
      } finally {
        if (originalEnvVar !== undefined) {
          process.env.DID_VERIFICATION_METHODS = originalEnvVar;
        } else {
          delete process.env.DID_VERIFICATION_METHODS;
        }
        if (originalEnvFile !== null) {
          fs.writeFileSync(ENV_FILE, originalEnvFile);
        } else {
          try {
            fs.unlinkSync(ENV_FILE);
          } catch {}
        }
      }
    });
  });
});

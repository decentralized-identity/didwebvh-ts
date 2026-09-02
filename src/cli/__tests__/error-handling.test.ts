import { afterEach, describe, expect, test, vi } from 'vitest';
import { CliError, handleCreate, handleDeactivate, handleResolve, handleUpdate, main } from '../index';

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
});

import { describe, expect, test } from 'vitest';
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
});

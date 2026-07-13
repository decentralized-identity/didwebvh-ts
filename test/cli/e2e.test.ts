import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { readLogFromDisk } from '../../src/cli/persistence';
import type { VerificationMethod } from '../../src/interfaces';
import { resolveDIDFromLog } from '../../src/method';
import { generateTestVerificationMethod, TestCryptoImplementation } from '../utils';

const TEST_DIR = join(process.cwd(), 'test', 'temp-cli-e2e');
const ENV_FILE = join(process.cwd(), '.env');

// Create a verifier for resolving CLI-created DIDs.
// TestCryptoImplementation.verify() does generic ed25519 verification
// using the public key from the proof, so a generic instance works.
let verifier: TestCryptoImplementation;
let savedEnv: string | null = null;

// Run a CLI command as a subprocess. --env-file=.env is passed directly to
// node so that process.env is populated from .env on startup — replicating
// the dotenv behaviour bun provided automatically.
function runCli(args: string[]) {
  const result = spawnSync(process.execPath, ['--env-file=.env', '--import', 'tsx/esm', 'src/cli/index.ts', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: process.env,
  });
  return { exitCode: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

beforeAll(async () => {
  const dummyKey = await generateTestVerificationMethod();
  verifier = new TestCryptoImplementation({ verificationMethod: dummyKey });
  fs.mkdirSync(TEST_DIR, { recursive: true });
  // Save existing .env content so we can restore it after tests
  try {
    savedEnv = fs.readFileSync(ENV_FILE, 'utf8');
  } catch {
    savedEnv = null;
  }
  // Clear DID_VERIFICATION_METHODS from both the .env file and process.env.
  // process.env takes precedence over --env-file values, so both must be cleaned.
  try {
    const content = savedEnv || '';
    const cleaned = content
      .split('\n')
      .filter((l) => !l.startsWith('DID_VERIFICATION_METHODS='))
      .join('\n');
    fs.writeFileSync(ENV_FILE, cleaned);
  } catch {}
  delete process.env.DID_VERIFICATION_METHODS;
});

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
  // Restore original .env content
  if (savedEnv !== null) {
    fs.writeFileSync(ENV_FILE, savedEnv);
  } else {
    try {
      fs.unlinkSync(ENV_FILE);
    } catch {}
  }
});

// Helper function to create a temporary verification method file for CLI commands
function createTempVerificationMethod(vm: VerificationMethod): string {
  const tempFile = join(TEST_DIR, `vm-${Date.now()}.json`);
  const vmData = Buffer.from(JSON.stringify([vm])).toString('base64');
  fs.writeFileSync(tempFile, vmData);
  return tempFile;
}

describe('CLI End-to-End Tests', () => {
  test('Create DID using CLI', async () => {
    const proc = runCli(['create', '--address', 'example.com', '--output', join(TEST_DIR, 'did.jsonl'), '--portable']);
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout).toContain('Created DID');
  });

  test('Update DID using CLI', async () => {
    const logFile = join(TEST_DIR, 'did-update.jsonl');

    // Create a DID — the CLI generates its own authKey and writes it to .env
    const createProc = runCli(['create', '--address', 'example.com', '--output', logFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // Update the DID — reads authKey from .env (loaded via NODE_OPTIONS=--env-file=.env)
    const updateProc = runCli(['update', '--log', logFile, '--output', logFile]);
    expect(updateProc.exitCode).toBe(0);

    // Verify the update was successful
    const log = await readLogFromDisk(logFile);
    expect(log).toHaveLength(2);
  });

  test('Second Update DID using CLI', async () => {
    const logFile = join(TEST_DIR, 'did-update2.jsonl');

    // Create a DID
    const createProc = runCli(['create', '--address', 'example.com', '--output', logFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // First update
    const update1Proc = runCli(['update', '--log', logFile, '--output', logFile]);
    expect(update1Proc.exitCode).toBe(0);

    // Second update
    const update2Proc = runCli(['update', '--log', logFile, '--output', logFile]);
    expect(update2Proc.exitCode).toBe(0);

    // Verify the updates were successful
    const log = await readLogFromDisk(logFile);
    expect(log).toHaveLength(3);
  });

  test('Deactivate DID using CLI', async () => {
    const logFile = join(TEST_DIR, 'did-deactivate.jsonl');

    // Create a DID
    const createProc = runCli(['create', '--address', 'example.com', '--output', logFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // Deactivate the DID — reads authKey from .env
    const deactivateProc = runCli(['deactivate', '--log', logFile, '--output', logFile]);
    expect(deactivateProc.exitCode).toBe(0);

    // Verify deactivation
    const log = await readLogFromDisk(logFile);
    const { meta } = await resolveDIDFromLog(log, { verifier });
    expect(meta.deactivated).toBe(true);
  });

  test('Create DID with prerotation', async () => {
    const prerotationLogFile = join(TEST_DIR, 'did-prerotation.jsonl');
    const nextKeyHash1 = 'nextKey1Hash';
    const nextKeyHash2 = 'nextKey2Hash';

    const proc = runCli([
      'create',
      '--address',
      'example.com',
      '--output',
      prerotationLogFile,
      '--portable',
      '--next-key-hash',
      nextKeyHash1,
      '--next-key-hash',
      nextKeyHash2,
    ]);
    expect(proc.exitCode).toBe(0);

    // Get the current authorized key and DID
    const currentLog = await readLogFromDisk(prerotationLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog, { verifier });
    const authorizedKey = meta.updateKeys[0];

    // Verify nextKeyHashes setup
    expect(currentLog[0].parameters.nextKeyHashes).toHaveLength(2);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash1);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash2);
  });

  test('Update DID with verification methods', async () => {
    const vmLogFile = join(TEST_DIR, 'did-vm.jsonl');

    // Create a DID
    const createProc = runCli(['create', '--address', 'example.com', '--output', vmLogFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // Get the DID
    const initialLog = await readLogFromDisk(vmLogFile);
    const { did } = await resolveDIDFromLog(initialLog, { verifier });

    // Add all VM types in a single update — reads authKey from .env
    const proc = runCli([
      'update',
      '--log',
      vmLogFile,
      '--output',
      vmLogFile,
      '--add-vm',
      'authentication',
      '--add-vm',
      'assertionMethod',
      '--add-vm',
      'keyAgreement',
      '--add-vm',
      'capabilityInvocation',
      '--add-vm',
      'capabilityDelegation',
    ]);
    expect(proc.exitCode).toBe(0);

    // Verify all VM types were added
    const finalLog = await readLogFromDisk(vmLogFile);
    const finalEntry = finalLog[finalLog.length - 1];

    // Get the authorized key from the final state
    const { meta: finalMeta } = await resolveDIDFromLog(finalLog, { verifier });
    const authorizedKey = finalMeta.updateKeys[0];

    const vmTypes = [
      'authentication',
      'assertionMethod',
      'keyAgreement',
      'capabilityInvocation',
      'capabilityDelegation',
    ] as const;
    const vmId = `${did}#${authorizedKey.slice(-8)}`;

    for (const vmType of vmTypes) {
      expect(finalEntry.state[vmType]).toBeDefined();
      expect(Array.isArray(finalEntry.state[vmType])).toBe(true);
      expect(finalEntry.state[vmType]).toContain(vmId);
    }
  });

  test('Update DID with alsoKnownAs', async () => {
    const akLogFile = join(TEST_DIR, 'did-aka.jsonl');

    // Create a DID
    const createProc = runCli(['create', '--address', 'example.com', '--output', akLogFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // Update with alsoKnownAs — reads authKey from .env
    const alias = 'https://example.com/users/123';
    const proc = runCli(['update', '--log', akLogFile, '--output', akLogFile, '--also-known-as', alias]);
    expect(proc.exitCode).toBe(0);

    // Verify alsoKnownAs was added
    const finalLog = await readLogFromDisk(akLogFile);
    const finalEntry = finalLog[finalLog.length - 1];

    expect(finalEntry.state.alsoKnownAs).toBeDefined();
    expect(Array.isArray(finalEntry.state.alsoKnownAs)).toBe(true);
    expect(finalEntry.state.alsoKnownAs).toContain(alias);
  });

  test('Resolve DID command', async () => {
    // First create a DID
    const resolveLogFile = join(TEST_DIR, 'did-resolve.jsonl');
    const createProc = runCli(['create', '--address', 'example.com', '--output', resolveLogFile, '--portable']);
    expect(createProc.exitCode).toBe(0);

    // Get the DID from the log
    const log = await readLogFromDisk(resolveLogFile);
    const { did } = await resolveDIDFromLog(log, { verifier });

    // Test resolve command with log file instead of DID
    const proc = runCli(['resolve', '--log', resolveLogFile]);
    expect(proc.exitCode).toBe(0);

    // Verify resolve output contains expected fields
    expect(proc.stdout).toContain('Resolved DID');
    expect(proc.stdout).toContain('DID Document');
    expect(proc.stdout).toContain('Metadata');
  });
});

describe('Witness CLI End-to-End Tests', () => {
  test('Create DID with witnesses using CLI', async () => {
    const logFile = join(TEST_DIR, 'did.jsonl');

    try {
      // Use the test implementation instead of generateEd25519VerificationMethod
      const witness = await generateTestVerificationMethod();
      // Witness ids are did:key DIDs (not DID URLs with fragments)
      const witnessDid = `did:key:${witness.publicKeyMultibase}`;

      // Run the CLI create command with witness
      const proc = runCli([
        'create',
        '--address',
        'localhost:8000',
        '--output',
        logFile,
        '--witness',
        witnessDid,
        '--witness-threshold',
        '1',
      ]);

      expect(proc.exitCode).toBe(0);

      // Verify the witness configuration
      const log = await readLogFromDisk(logFile);

      // Add null checks for TypeScript
      if (!log[0]?.parameters?.witness) {
        throw new Error('Witness configuration not found in DID log');
      }

      expect(log[0].parameters.witness.witnesses).toHaveLength(1);
      expect(log[0].parameters.witness.witnesses?.[0]?.id).toBe(witnessDid);
      expect(log[0].parameters.witness.threshold).toBe(1);
    } catch (error) {
      console.error('Error in witness test:', error);
      throw error;
    }
  });

  test('Generate witness proof for multiple version IDs', async () => {
    const witness = await generateTestVerificationMethod();
    const witnessDid = `did:key:${witness.publicKeyMultibase}`;
    const outputFile = join(TEST_DIR, 'did-witness-multi.json');

    const proc = runCli([
      'generate-witness-proof',
      '--version-id',
      '1-abc123',
      '--version-id',
      '2-def456',
      '--witness-did',
      witnessDid,
      '--witness-secret',
      witness.secretKeyMultibase!,
      '--output',
      outputFile,
    ]);
    expect(proc.exitCode).toBe(0);

    const content = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
    expect(Array.isArray(content)).toBe(true);
    expect(content).toHaveLength(2);
    expect(content[0].versionId).toBe('1-abc123');
    expect(content[1].versionId).toBe('2-def456');
    expect(content[0].proof).toHaveLength(1);
    expect(content[1].proof).toHaveLength(1);
    expect(content[0].proof[0].proofPurpose).toBe('assertionMethod');
    expect(content[1].proof[0].proofPurpose).toBe('assertionMethod');
  });
});

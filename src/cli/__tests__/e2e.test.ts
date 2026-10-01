import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import {
  createTestDIDDocument,
  createTestSigner,
  createTestVerifier,
  createWitnessProof,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from '../../../test/utils.js';
import type { WitnessProofFileEntry } from '../../interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../../method.js';
import { deriveNextKeyHash } from '../../utils/crypto.js';
import { type CliSigningKey, readLogFromDisk, writeLogToDisk } from '../persistence.js';

const REPO_ROOT = process.cwd();
const TEST_DIR = join(REPO_ROOT, 'test', 'temp-cli-e2e');
// CLI subprocesses run with cwd: TEST_DIR (see runCli below) so that
// writeVerificationMethodToEnv()/getVerificationMethodsFromEnv(), which both resolve to
// `${process.cwd()}/.env`, read and write an isolated .env instead of the real repo-root one.
// error-handling.test.ts touches the same real .env when run directly, so sharing it here would
// risk both suites racing to save/restore/truncate the same file.
const CLI_ENTRY = join(REPO_ROOT, 'src', 'cli', 'index.ts');
const ISOLATED_ENV_FILE = join(TEST_DIR, '.env');

// Create a verifier for resolving CLI-created DIDs.
// TestCryptoImplementation.verify() does generic ed25519 verification
// using the public key from the proof, so a generic instance works.
let verifier: TestCryptoImplementation;

// Run a CLI command as a subprocess. --env-file=.env is passed directly to
// node so that process.env is populated from .env on startup.
function runCli(args: string[]) {
  const result = spawnSync(process.execPath, ['--env-file=.env', '--import', 'tsx/esm', CLI_ENTRY, ...args], {
    cwd: TEST_DIR,
    encoding: 'utf8',
    env: process.env,
  });
  return { exitCode: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

beforeAll(async () => {
  const dummyKey = await generateTestVerificationMethod();
  verifier = new TestCryptoImplementation({ verificationMethod: dummyKey });
  fs.mkdirSync(TEST_DIR, { recursive: true });
  // Start with a fresh, empty isolated .env — node's --env-file requires the file to exist.
  fs.writeFileSync(ISOLATED_ENV_FILE, '');
  // process.env takes precedence over --env-file values and is inherited by the CLI subprocess
  // (see runCli's env: process.env), so clear it here too.
  delete process.env.DID_VERIFICATION_METHODS;
});

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
});

// Helper function to create a temporary verification method file for CLI commands
function createTempVerificationMethod(vm: CliSigningKey): string {
  const tempFile = join(TEST_DIR, `vm-${Date.now()}.json`);
  const vmData = Buffer.from(JSON.stringify([vm])).toString('base64');
  fs.writeFileSync(tempFile, vmData);
  return tempFile;
}

describe('Controller CLI End-to-End Tests', () => {
  test('Create DID using CLI', async () => {
    const logFile = join(TEST_DIR, 'did.jsonl');
    const proc = runCli(['create', '--address', 'example.com', '--output', logFile, '--portable']);
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout).toContain('Created DID');

    const log = await readLogFromDisk(logFile);
    expect(log[0].state.service).toBeUndefined();

    const resolved = await resolveDIDFromLog(log, { verifier });
    const did = resolved.didDocument?.id;
    const serviceIds = (resolved.didDocument?.service ?? []).map((service) => service.id);

    expect(serviceIds).toContain(`${did}#files`);
    expect(serviceIds).toContain(`${did}#whois`);
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
    const { didDocumentMetadata: meta } = await resolveDIDFromLog(log, { verifier });
    expect(meta.deactivated).toBe(true);
  });

  test('Create DID with prerotation', async () => {
    const prerotationLogFile = join(TEST_DIR, 'did-prerotation.jsonl');
    const nextKey1 = await generateTestVerificationMethod();
    const nextKey2 = await generateTestVerificationMethod();
    if (!nextKey1.publicKeyMultibase || !nextKey2.publicKeyMultibase) {
      throw new Error('Generated next keys are missing publicKeyMultibase');
    }
    const nextKeyHash1 = await deriveNextKeyHash(nextKey1.publicKeyMultibase);
    const nextKeyHash2 = await deriveNextKeyHash(nextKey2.publicKeyMultibase);

    const proc = runCli([
      'create',
      '--address',
      'example.com',
      '--output',
      prerotationLogFile,
      '--portable',
      '--next-key',
      `did:key:${nextKey1.publicKeyMultibase}`,
      '--next-key-hash',
      nextKeyHash2,
    ]);
    expect(proc.exitCode).toBe(0);

    // Get the current authorized key and DID
    const currentLog = await readLogFromDisk(prerotationLogFile);
    const r = await resolveDIDFromLog(currentLog, { verifier });
    const did = r.didDocument?.id;
    const meta = r.didDocumentMetadata;
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
    const initialResolution = await resolveDIDFromLog(initialLog, { verifier });
    const did = initialResolution.didDocument?.id;

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
    const { didDocumentMetadata: finalMeta } = await resolveDIDFromLog(finalLog, { verifier });
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

  test('Update DID with prerotation convenience key', async () => {
    const prerotationUpdateLogFile = join(TEST_DIR, 'did-update-prerotation.jsonl');
    const createProc = runCli([
      'create',
      '--address',
      'example.com',
      '--output',
      prerotationUpdateLogFile,
      '--portable',
    ]);
    expect(createProc.exitCode).toBe(0);

    const nextKey1 = await generateTestVerificationMethod();
    const nextKey2 = await generateTestVerificationMethod();
    if (!nextKey1.publicKeyMultibase || !nextKey2.publicKeyMultibase) {
      throw new Error('Generated next keys are missing publicKeyMultibase');
    }
    const nextKeyHash1 = await deriveNextKeyHash(nextKey1.publicKeyMultibase);
    const nextKeyHash2 = await deriveNextKeyHash(nextKey2.publicKeyMultibase);

    const proc = runCli([
      'update',
      '--log',
      prerotationUpdateLogFile,
      '--output',
      prerotationUpdateLogFile,
      '--next-key',
      `did:key:${nextKey1.publicKeyMultibase}`,
      '--next-key-hash',
      nextKeyHash2,
    ]);
    expect(proc.exitCode).toBe(0);

    const updatedLog = await readLogFromDisk(prerotationUpdateLogFile);
    const updatedEntry = updatedLog[updatedLog.length - 1];

    expect(updatedEntry.parameters.nextKeyHashes).toHaveLength(2);
    expect(updatedEntry.parameters.nextKeyHashes).toContain(nextKeyHash1);
    expect(updatedEntry.parameters.nextKeyHashes).toContain(nextKeyHash2);
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
    const resolveResolution = await resolveDIDFromLog(log, { verifier });
    const did = resolveResolution.didDocument?.id;

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

  test('Generate a witness proof for a candidate log using CLI', async () => {
    const trustedLogFile = join(TEST_DIR, 'trusted-witness-log.jsonl');
    const candidateLogFile = join(TEST_DIR, 'candidate-witness-log.jsonl');
    const historicalProofFile = join(TEST_DIR, 'historical-witness-proof.json');
    const proofFile = join(TEST_DIR, 'witness-proof.json');
    const controller = await generateTestVerificationMethod();
    const witness = await generateTestVerificationMethod();
    const controllerSigner = createTestSigner(controller);
    const witnessSigner = createTestSigner(witness);
    const verifier = createTestVerifier(controller);
    if (!controller.publicKeyMultibase || !witness.secretKeyMultibase) {
      throw new Error('Generated test verification methods must contain key material');
    }
    const witnessDid = `did:key:${witness.publicKeyMultibase}`;

    const trusted = await createDID({
      address: 'localhost:8000',
      signer: controllerSigner,
      updateKeys: [controller.publicKeyMultibase],
      didDocument: createTestDIDDocument(controller),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier,
    });
    const genesisProof = await createWitnessProof(
      async (document, proof) => {
        if (!proof) {
          throw new Error('Witness proof template is required');
        }
        return { proof: await witnessSigner.sign({ document, proof }) };
      },
      trusted.log[0].versionId,
      witnessSigner.getVerificationMethodId()
    );
    const candidate = await updateDID({
      log: trusted.log,
      signer: controllerSigner,
      verifier,
      witnessProofs: [{ versionId: trusted.log[0].versionId, proof: [genesisProof] }],
    });

    fs.writeFileSync(
      historicalProofFile,
      JSON.stringify([{ versionId: trusted.log[0].versionId, proof: [genesisProof] }], null, 2)
    );
    await writeLogToDisk(trustedLogFile, trusted.log);
    await writeLogToDisk(candidateLogFile, candidate.log);

    const proc = runCli([
      'generate-witness-proof',
      '--trusted-log',
      trustedLogFile,
      '--candidate-log',
      candidateLogFile,
      '--witness-did',
      witnessDid,
      '--witness-secret',
      witness.secretKeyMultibase,
      '--witness-file',
      historicalProofFile,
      '--output',
      proofFile,
    ]);

    expect(proc.exitCode, proc.stderr).toBe(0);
    expect(proc.stdout).toContain('Witness proof file generated');

    const witnessProofs = JSON.parse(fs.readFileSync(proofFile, 'utf8')) as WitnessProofFileEntry[];
    expect(witnessProofs).toHaveLength(1);
    expect(witnessProofs[0]?.versionId).toBe(candidate.log[1]?.versionId);
    expect(witnessProofs[0]?.proof).toHaveLength(1);

    await expect(
      resolveDIDFromLog(candidate.log, {
        verifier,
        witnessProofs,
      })
    ).resolves.toMatchObject({
      didDocument: { id: expect.any(String) },
    });
  });
});

import { describe, expect, test, beforeAll, afterAll, it } from "bun:test";
import fs from 'node:fs';
import { join } from 'path';
import { readLogFromDisk, readLogFromString } from "../src/utils";
import { $ } from "bun";
import { resolveDIDFromLog } from "../src/method";
import { generateEd25519VerificationMethod } from "../src/cryptography";
import { generateTestVerificationMethod } from "./utils";

// Set environment variables for tests
process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID = 'true';

const TEST_DIR = './test/temp-cli-e2e';

describe("CLI End-to-End Tests", () => {
  const TEST_LOG_FILE = join(TEST_DIR, 'did.jsonl');
  let currentDID: string;
  
  beforeAll(async () => {
    // Create test directory if it doesn't exist
    if (!fs.existsSync(TEST_DIR)) {
      fs.mkdirSync(TEST_DIR, { recursive: true });
    }
  });

  afterAll(() => {
    // Clean up test files
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true });
    }
  });

  test("Create DID using CLI", async () => {
    // Run the CLI create command
    const proc = await $`bun run cli create --domain example.com --output ${TEST_LOG_FILE} --portable`;

    expect(proc.exitCode).toBe(0);
    
    // Verify the log file was created
    expect(fs.existsSync(TEST_LOG_FILE)).toBe(true);
    
    // Read and verify the log content
    const log = readLogFromDisk(TEST_LOG_FILE);
    expect(log).toHaveLength(1);
    expect(log[0].parameters.portable).toBe(true);
    expect(log[0].parameters.method).toBe('did:webvh:0.5');
    
    // Get the DID from the log
    const { did, meta } = await resolveDIDFromLog(log);
    currentDID = did;

    // Read the verification method directly from .env file
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse and set the VM in the current process
    const vm = JSON.parse(Buffer.from(vmMatch[1], 'base64').toString('utf8'))[0];
    process.env.DID_VERIFICATION_METHODS = vmMatch[1];
  });

  test("Update DID using CLI", async () => {
    // Read the current log to get the latest state
    const currentLog = readLogFromDisk(TEST_LOG_FILE);
    const { meta } = await resolveDIDFromLog(currentLog);

    // Get the authorized key from meta
    const authorizedKey = meta.updateKeys[0];

    // Run the CLI update command to add a service, using the authorized key
    const proc = await $`bun run cli update --log ${TEST_LOG_FILE} --output ${TEST_LOG_FILE} --service LinkedDomains,https://example.com --update-key ${authorizedKey}`.quiet();

    expect(proc.exitCode).toBe(0);
    
    // Verify the update
    const log = readLogFromDisk(TEST_LOG_FILE);
    expect(log).toHaveLength(2);
    
    // Check if service was added
    const lastEntry = log[log.length - 1];
    expect(lastEntry.state?.service).toBeDefined();
    if (lastEntry.state?.service) {
      expect(lastEntry.state.service[0].type).toBe('LinkedDomains');
    }
  });

  test("Second Update DID using CLI", async () => {
    // Read the current log to get the latest state
    const currentLog = readLogFromDisk(TEST_LOG_FILE);
    const { meta } = await resolveDIDFromLog(currentLog);

    // Get the authorized key from meta
    const authorizedKey = meta.updateKeys[0];

    // Run the CLI update command to add another service, using the authorized key
    const proc = await $`bun run cli update --log ${TEST_LOG_FILE} --output ${TEST_LOG_FILE} --service NewService,https://newservice.example.com --update-key ${authorizedKey}`.quiet();
  
    expect(proc.exitCode).toBe(0);
    
    // Verify the update
    const log = readLogFromDisk(TEST_LOG_FILE);
    expect(log).toHaveLength(3);
    
    // Check if new service was added
    const lastEntry = log[log.length - 1];
    expect(lastEntry.state?.service).toBeDefined();
    if (lastEntry.state?.service) {
      expect(lastEntry.state.service[0].type).toBe('NewService');
    }
  });

  test("Deactivate DID using CLI", async () => {
    // Read the current log to get the latest state
    const currentLog = readLogFromDisk(TEST_LOG_FILE);
    const { meta } = await resolveDIDFromLog(currentLog);

    // Read the current verification method from env
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse and update the VM with the current authorized key
    const vm = JSON.parse(Buffer.from(vmMatch[1], 'base64').toString('utf8'))[0];
    vm.publicKeyMultibase = meta.updateKeys[0];
    process.env.DID_VERIFICATION_METHODS = Buffer.from(JSON.stringify([vm])).toString('base64');

    // Run the CLI deactivate command
    const proc = await $`bun run cli deactivate --log ${TEST_LOG_FILE} --output ${TEST_LOG_FILE}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify the deactivation
    const log = readLogFromDisk(TEST_LOG_FILE);
    const lastEntry = log[log.length - 1];
    expect(lastEntry.parameters.deactivated).toBe(true);
  });

  test("Create DID with prerotation", async () => {
    const prerotationLogFile = join(TEST_DIR, 'did-prerotation.jsonl');
    
    // First create a DID with nextKeyHashes
    const nextKeyHash1 = "z6MkgYGF3thn8k1Qz9P4c3mKthZXNhUgkdwBwE5hbWFJktGH";
    const nextKeyHash2 = "z6MkrCD1Qr8TQ4SQNzpkwx8qRLFQkUg7oKc8rjhYoV6DpHXx";
    
    const createProc = await $`bun run cli create --domain example.com --output ${prerotationLogFile} --portable --next-key-hash ${nextKeyHash1} --next-key-hash ${nextKeyHash2}`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Wait a moment for the .env file to be written
    await new Promise(resolve => setTimeout(resolve, 100));

    // Get the current authorized key and DID
    const currentLog = readLogFromDisk(prerotationLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog);
    const authorizedKey = meta.updateKeys[0];
    
    // Verify nextKeyHashes setup
    expect(currentLog[0].parameters.nextKeyHashes).toHaveLength(2);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash1);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash2);
  });

  test("Update DID with verification methods", async () => {
    const vmLogFile = join(TEST_DIR, 'did-vm.jsonl');
    
    // First create a DID
    const createProc = await $`bun run cli create --domain example.com --output ${vmLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Wait a moment for the .env file to be written
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get the current authorized key and DID
    const currentLog = readLogFromDisk(vmLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog);
    const authorizedKey = meta.updateKeys[0];

    // Read and parse the VM from env
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse and update the VM with the current authorized key
    const vm = JSON.parse(Buffer.from(vmMatch[1], 'base64').toString('utf8'))[0];
    vm.publicKeyMultibase = authorizedKey;
    vm.controller = did;
    vm.id = `${did}#${authorizedKey.slice(-8)}`;
    process.env.DID_VERIFICATION_METHODS = Buffer.from(JSON.stringify([vm])).toString('base64');
    
    // Add all VM types in a single update
    const proc = await $`bun run cli update --log ${vmLogFile} --output ${vmLogFile} --add-vm authentication --add-vm assertionMethod --add-vm keyAgreement --add-vm capabilityInvocation --add-vm capabilityDelegation --update-key ${authorizedKey}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify all VM types were added
    const finalLog = readLogFromDisk(vmLogFile);
    const finalEntry = finalLog[finalLog.length - 1];
    
    const vmTypes = ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'] as const;
    const vmId = `${did}#${authorizedKey.slice(-8)}`;
    
    for (const vmType of vmTypes) {
        expect(finalEntry.state[vmType]).toBeDefined();
        expect(Array.isArray(finalEntry.state[vmType])).toBe(true);
        expect(finalEntry.state[vmType]).toContain(vmId);
    }
  });

  test("Update DID with alsoKnownAs", async () => {
    const akLogFile = join(TEST_DIR, 'did-aka.jsonl');
    
    // First create a DID
    const createProc = await $`bun run cli create --domain example.com --output ${akLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Wait a moment for the .env file to be written
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get the current authorized key and DID
    const currentLog = readLogFromDisk(akLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog);
    const authorizedKey = meta.updateKeys[0];

    // Read and parse the VM from env
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse and update the VM with the current authorized key
    const vm = JSON.parse(Buffer.from(vmMatch[1], 'base64').toString('utf8'))[0];
    vm.publicKeyMultibase = authorizedKey;
    vm.controller = did;
    process.env.DID_VERIFICATION_METHODS = Buffer.from(JSON.stringify([vm])).toString('base64');
    
    // Update with alsoKnownAs
    const alias = 'https://example.com/users/123';
    const proc = await $`bun run cli update --log ${akLogFile} --output ${akLogFile} --also-known-as ${alias} --update-key ${authorizedKey}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify alsoKnownAs was added
    const finalLog = readLogFromDisk(akLogFile);
    const lastEntry = finalLog[finalLog.length - 1];
    expect(lastEntry.state.alsoKnownAs).toBeDefined();
    expect(Array.isArray(lastEntry.state.alsoKnownAs)).toBe(true);
    expect(lastEntry.state.alsoKnownAs).toContain(alias);
  });

  test("Resolve DID command", async () => {
    // First create a DID
    const resolveLogFile = join(TEST_DIR, 'did-resolve.jsonl');
    const createProc = await $`bun run cli create --domain example.com --output ${resolveLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Get the DID from the log
    const log = readLogFromDisk(resolveLogFile);
    const { did } = await resolveDIDFromLog(log);
    
    // Test resolve command with log file instead of DID
    const proc = await $`bun run cli resolve --log ${resolveLogFile}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify resolve output contains expected fields
    const output = proc.stdout.toString();
    expect(output).toContain('Resolved DID');
    expect(output).toContain('DID Document');
    expect(output).toContain('Metadata');
  });
}); 

describe("Witness CLI End-to-End Tests", async () => {
  test("Create DID with witnesses using CLI", async () => {
    const logFile = join(TEST_DIR, 'did.jsonl');
    
    try {
      // Use the test implementation instead of generateEd25519VerificationMethod
      const witness = await generateTestVerificationMethod();
      // Parse the witness log and get the verification key from the state
      const witnessDIDKey = `did:key:${witness.publicKeyMultibase}#${witness.publicKeyMultibase}`;
      
      // Run the CLI create command with witness
      const proc = await $`bun run cli create --domain localhost:8000 --output ${logFile} --witness ${witnessDIDKey} --witness-threshold 1`.quiet();

      expect(proc.exitCode).toBe(0);
      
      // Verify the witness configuration
      const log = readLogFromDisk(logFile);
      
      // Add null checks for TypeScript
      if (!log[0]?.parameters?.witness) {
        throw new Error('Witness configuration not found in DID log');
      }
      
      expect(log[0].parameters.witness.witnesses).toHaveLength(1);
      expect(log[0].parameters.witness.witnesses[0].id).toBe(witnessDIDKey);
      expect(log[0].parameters.witness.threshold).toBe(1);
    } catch (error) {
      console.error('Error in witness test:', error);
      throw error;
    }
  });
});

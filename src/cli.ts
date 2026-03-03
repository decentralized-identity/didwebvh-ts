#!/usr/bin/env node

import { createDID, updateDID, deactivateDID, resolveDIDFromLog } from './method';
import { fetchLogFromIdentifier, readLogFromDisk, writeLogToDisk, writeVerificationMethodToEnv } from './utils';
import { dirname } from 'path';
import fs from 'fs';
import { DIDLog, ServiceEndpoint, VerificationMethod, Verifier } from './interfaces';
import { createBuffer } from './utils/buffer';
import { bufferToString } from './utils/buffer';
import { Signer, SigningInput, SigningOutput } from './interfaces';
import { multibaseEncode } from './utils/multiformats';
import { MultibaseEncoding } from './utils/multiformats';
import { verify as ed25519Verify } from '@stablelib/ed25519';
import { sign as ed25519Sign } from '@stablelib/ed25519';
import { canonicalize } from 'json-canonicalize';
import { concatBuffers } from './utils/buffer';
import { createHash } from './utils/crypto';
import { multibaseDecode } from './utils/multiformats';
import { generateKeyPair } from '@stablelib/ed25519';

import { createWitnessProof } from './witness';

const usage = `
Usage: bun run cli [command] [options]

Commands:
  create     Create a new DID
  resolve    Resolve a DID
  update     Update an existing DID
  deactivate Deactivate an existing DID
  generate-witness-proof Generate witness proofs for a DID version
  generate-vm Generate a new verification method keypair

Options:
  --domain [domain]         Domain for the DID (required for create)
  --log [file]              Path to the DID log file (required for resolve, update, deactivate)
  --output [file]           Path to save the updated DID log (optional for create, update, deactivate)
  --portable                Make the DID portable (optional for create)
  --witness [witness]       Add a witness (can be used multiple times)
  --witness-threshold [n]   Set witness threshold (optional, defaults to number of witnesses)
  --watcher [url]           Add a watcher URL (can be used multiple times)
  --service [service]       Add a service (format: type,endpoint) (can be used multiple times)
  --add-vm [type]           Add a verification method (type can be authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation)
  --also-known-as [alias]   Add an alsoKnownAs alias (can be used multiple times)
  --next-key-hash [hash]    Add a nextKeyHash (can be used multiple times)
  --witness-file [file]     Path to witness proofs file (optional for resolve)

  # Options for generate-witness-proof:
  --version-id [id]         The version ID to generate proofs for (required)
  --witness-did [did]       Witness DID (did:key) (can be used multiple times)
  --witness-secret [secret] Witness secret key multibase (matches witness-did order)

Examples:
  bun run cli create --domain example.com --portable --witness did:example:witness1 --witness did:example:witness2
  bun run cli resolve --did did:webvh:123456:example.com
  bun run cli resolve --log ./did.jsonl --witness-file ./did-witness.json
  bun run cli update --log ./did.jsonl --output ./updated-did.jsonl --add-vm keyAgreement --service LinkedDomains,https://example.com
  bun run cli deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
  bun run cli generate-witness-proof --version-id 1-abc123 --witness-did did:key:z6Mk... --witness-secret z1A... --output did-witness.json
  bun run cli generate-vm
`;

// Add this function at the top with the other constants
function showHelp() {
  console.log(usage);
}

async function generateVerificationMethod(purpose: "authentication" | "assertionMethod" | "keyAgreement" | "capabilityInvocation" | "capabilityDelegation" = 'authentication'): Promise<VerificationMethod> {
  const keyPair = generateKeyPair();
  const publicKeyBytes = new Uint8Array([0xed, 0x01, ...keyPair.publicKey]);
  const secretKeyBytes = new Uint8Array([0x80, 0x26, ...keyPair.secretKey]);
  return {
    type: 'Multikey',
    publicKeyMultibase: multibaseEncode(publicKeyBytes, MultibaseEncoding.BASE58_BTC),
    secretKeyMultibase: multibaseEncode(secretKeyBytes, MultibaseEncoding.BASE58_BTC),
    purpose
  };
}
class CustomCryptoImplementation implements Signer, Verifier {
  private verificationMethod?: VerificationMethod;
  
  constructor(verificationMethod?: VerificationMethod) {
    this.verificationMethod = verificationMethod;
  }
  
  getVerificationMethodId(): string {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
    return `did:key:${this.verificationMethod.publicKeyMultibase}#${this.verificationMethod.publicKeyMultibase}`;
  }
  
  async sign(input: SigningInput): Promise<SigningOutput> {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
    const { document, proof } = input;
    const dataHash = await createHash(canonicalize(document));
    const proofHash = await createHash(canonicalize(proof));
    const message = concatBuffers(proofHash, dataHash);
    const secretKey = multibaseDecode(this.verificationMethod.secretKeyMultibase!).bytes.slice(2);
    const signature = ed25519Sign(secretKey, message);
    return {
      proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC)
    };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return ed25519Verify(publicKey, message, signature);
  }
}

function createCustomCrypto(verificationMethod?: VerificationMethod): Signer & Verifier {
  return new CustomCryptoImplementation(verificationMethod);
}

export async function handleCreate(args: string[]) {
  const options = parseOptions(args);
  const domainInput = options['domain'] as string;
  const parts = domainInput.split('/');
  const domain = parts[0];
  const paths = parts.length > 1 ? parts.slice(1) : undefined;
  const output = options['output'] as string | undefined;
  const portable = options['portable'] !== undefined;
  const nextKeyHashes = options['next-key-hash'] as string[] | undefined;
  const witnesses = options['witness'] as string[] | undefined;
  const watchers = options['watcher'] as string[] | undefined;
  const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold'] as string) : witnesses?.length ?? 0;

  if (!domain) {
    console.error('Domain is required for create command');
    process.exit(1);
  }

  try {
    const authKey = await generateVerificationMethod();
    const crypto = createCustomCrypto(authKey)
    
    // Strip secret key from verification method for DID document (security)
    const publicAuthKey = {
      id: authKey.id,
      type: authKey.type,
      controller: authKey.controller,
      publicKeyMultibase: authKey.publicKeyMultibase,
      purpose: authKey.purpose
    };
    
    const { did, doc, meta, log } = await createDID({
      domain,
      paths,
      signer: crypto,
      verifier: crypto,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [publicAuthKey],
      portable,
      witness: witnesses?.length ? {
        witnesses: witnesses.map(witness => ({id: witness})),
        threshold: witnessThreshold
      } : undefined,
      watchers: watchers ?? undefined,
      nextKeyHashes,
    });

    console.log('Created DID:', did);

    if (output) {
      // Ensure output directory exists
      const outputDir = dirname(output);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      // Write log to file
      await writeLogToDisk(output, log);
      console.log(`DID log written to ${output}`);

      // Save verification method to env
      await writeVerificationMethodToEnv({
        ...authKey, 
        controller: did, 
        id: `${did}#${authKey.publicKeyMultibase?.slice(-8)}`
      });
      console.log(`DID verification method saved to env`);

    } else {
      // If no output specified, print to console
      console.log('DID Document:', JSON.stringify(doc, null, 2));
      console.log('DID Log:', JSON.stringify(log, null, 2));
    }

    return { did, doc, meta, log };
  } catch (error) {
    console.error('Error creating DID:', error);
    process.exit(1);
  }
}

export async function handleResolve(args: string[]) {
  const options = parseOptions(args);
  const didIdentifier = options['did'] as string;
  const logFile = options['log'] as string;
  const witnessFile = options['witness-file'] as string | undefined;

  if (!didIdentifier && !logFile) {
    console.error('Either --did or --log is required for resolve command');
    process.exit(1);
  }

  try {
    let log: DIDLog;
    if (logFile) {
      log = await readLogFromDisk(logFile);
    } else {
      log = await fetchLogFromIdentifier(didIdentifier);
    }

    let resolutionOptions: any = {};
    if (witnessFile) {
      const witnessProofs = JSON.parse(fs.readFileSync(witnessFile, 'utf8'));
      resolutionOptions.witnessProofs = witnessProofs;
    }
    const crypto = createCustomCrypto();
    resolutionOptions.verifier = crypto;

    console.time('Resolution time');
    const { did, doc, meta } = await resolveDIDFromLog(log, resolutionOptions);
    console.timeEnd('Resolution time');

    console.log('Resolved DID:', did);
    console.log('DID Document:', JSON.stringify(doc, null, 2));
    console.log('Metadata:', JSON.stringify(meta, null, 2));

    return { did, doc, meta };
  } catch (error) {
    console.error('Error resolving DID:', error);
    process.exit(1);
  }
}

export async function handleUpdate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options['log'] as string;
  const output = options['output'] as string | undefined;
  const witnesses = options['witness'] as string[] | undefined;
  const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold'] as string) : undefined;
  const services = options['service'] ? parseServices(options['service'] as string[]) : undefined;
  const addVm = options['add-vm'] as string[] | undefined;
  const alsoKnownAs = options['also-known-as'] as string[] | undefined;
  const updateKey = options['update-key'] as string | undefined;
  const watchers = options['watcher'] as string[] | undefined;

  if (!logFile) {
    console.error('Log file is required for update command');
    process.exit(1);
  }

  try {
    const log = await readLogFromDisk(logFile);
    const { did, meta } = await resolveDIDFromLog(log, { verifier: createCustomCrypto() });
    // console.log('\nCurrent DID:', did);
    // console.log('Current meta:', meta);
    
    // Get the verification method from environment
    const envVMs = JSON.parse(bufferToString(createBuffer(process.env.DID_VERIFICATION_METHODS || 'W10=', 'base64')));
    
    let vm = envVMs.find((vm: any) => vm.controller === did);
    
    if (!vm) {
      // Try to find VM by matching public key with current update keys
      vm = envVMs.find((vm: any) => meta.updateKeys.includes(vm.publicKeyMultibase));
    }
    
    if (!vm && envVMs.length > 0) {
      // Fall back to first available VM with warning
      console.warn('Warning: No matching verification method found for DID or update keys. Using first available VM.');
      vm = envVMs[0];
    }
    
    // console.log('\nFound VM:', vm);
    
    if (!vm) {
      throw new Error('No verification method found in environment');
    }

    // Create verification methods array
    const verificationMethods: VerificationMethod[] = [];
    
    // If we're adding VMs, create a VM for each type
    if (addVm && addVm.length > 0) {
      const vmId = `${did}#${vm.publicKeyMultibase!.slice(-8)}`;
      
      // Add a verification method for each type
      for (const vmType of addVm) {
        const newVM: VerificationMethod = {
          id: vmId,
          type: "Multikey",
          controller: did,
          publicKeyMultibase: vm.publicKeyMultibase,
          purpose: vmType as VerificationMethodType
        };
        verificationMethods.push(newVM);
      }
    } else {
      // For non-VM updates (services, alsoKnownAs), still need a VM with purpose
      verificationMethods.push({
        id: `${did}#${vm.publicKeyMultibase!.slice(-8)}`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: vm.publicKeyMultibase,
        purpose: "assertionMethod"
      });
    }

    const crypto = createCustomCrypto(vm);
    const result = await updateDID({
      log,
      signer: crypto,
      verifier: crypto,
      updateKeys: [vm.publicKeyMultibase!],
      verificationMethods,
      witness: witnesses?.length ? {
        witnesses: witnesses.map(witness => ({id: witness})),
        threshold: witnessThreshold ?? witnesses.length
      } : undefined,
      watchers: watchers ?? undefined,
      services,
      alsoKnownAs
    });

    if (output) {
      await writeLogToDisk(output, result.log);
      console.log(`Updated DID log written to ${output}`);
    }

    return result;
  } catch (error) {
    console.error('Error updating DID:', error);
    process.exit(1);
  }
}

export async function handleDeactivate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options['log'] as string;
  const output = options['output'] as string | undefined;

  if (!logFile) {
    console.error('Log file is required for deactivate command');
    process.exit(1);
  }

  try {
    // Read the current log to get the latest state
    const log = await readLogFromDisk(logFile);
    const { did, meta } = await resolveDIDFromLog(log, { verifier: createCustomCrypto() });
    
    // Get the verification method from environment
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse the VM from env
    const vms = JSON.parse(bufferToString(createBuffer(vmMatch[1], 'base64')));
    if (!vms || vms.length === 0) {
      throw new Error('No verification method found in environment');
    }

    // Find VM that matches the current update key
    let vm = vms.find((v: any) => v.publicKeyMultibase === meta.updateKeys[0]);
    
    if (!vm) {
      // If no matching VM found, use the first one and warn
      console.warn('Warning: No matching verification method found for current update key. Using first available VM.');
      vm = vms[0];
    }

    // Don't modify the publicKeyMultibase - it should match the secretKeyMultibase

    const crypto = createCustomCrypto(vm);
    const result = await deactivateDID({
      log,
      signer: crypto,
      verifier: crypto,
    });

    if (output) {
      await writeLogToDisk(output, result.log);
      console.log(`Deactivated DID log written to ${output}`);
    }

    return result;
  } catch (error) {
    console.error('Error deactivating DID:', error);
    process.exit(1);
  }
}

async function handleGenerateWitnessProof(args: string[]) {
  const options = parseOptions(args);
  const versionId = options['version-id'] as string;
  const witnessDids = options['witness-did'] as string[] | undefined;
  const witnessSecrets = options['witness-secret'] as string[] | undefined;
  const output = options['output'] as string;

  if (!versionId) {
    console.error('Version ID is required');
    process.exit(1);
  }
  if (!output) {
    console.error('Output file is required');
    process.exit(1);
  }
  if (!witnessDids || !witnessSecrets || witnessDids.length !== witnessSecrets.length) {
    console.error('Must provide matching number of witness DIDs and secrets');
    process.exit(1);
  }

  const proofs = [];
  for (let i = 0; i < witnessDids.length; i++) {
    const did = witnessDids[i];
    const secret = witnessSecrets[i];
    const publicKeyMultibase = did.split(':')[2];
    const vm: VerificationMethod = {
      type: 'Multikey',
      publicKeyMultibase,
      secretKeyMultibase: secret,
      purpose: 'authentication'
    };
    const crypto = createCustomCrypto(vm);
    const signerFn = async (data: any) => {
      const proofTemplate = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: `${did}#${publicKeyMultibase}`,
        created: new Date().toISOString(),
        proofPurpose: 'authentication'
      };
      const signingInput = { document: data, proof: proofTemplate };
      const signed = await crypto.sign(signingInput);
      return { proof: { ...proofTemplate, proofValue: signed.proofValue } };
    };
    const proof = await createWitnessProof(signerFn, versionId);
    proofs.push(proof);
  }

  const witnessFileContent = [{
    versionId,
    proof: proofs
  }];

  fs.writeFileSync(output, JSON.stringify(witnessFileContent, null, 2));
  console.log(`Witness proof file generated at ${output}`);
}

type VerificationMethodType = 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';

function parseOptions(args: string[]): Record<string, string | string[] | undefined> {
  const options: Record<string, string | string[] | undefined> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        if (key === 'witness' || key === 'service' || key === 'also-known-as' || key === 'next-key-hash' || key === 'watcher' || key === 'witness-did' || key === 'witness-secret') {
          options[key] = options[key] || [];
          (options[key] as string[]).push(args[++i]);
        } else if (key === 'add-vm') {
          options[key] = options[key] || [];
          const value = args[++i];
          if (isValidVerificationMethodType(value)) {
            (options[key] as VerificationMethodType[]).push(value);
          } else {
            console.error(`Invalid verification method type: ${value}`);
            process.exit(1);
          }
        } else {
          options[key] = args[++i];
        }
      } else {
        options[key] = '';
      }
    }
  }
  return options;
}

// Add this function to validate VerificationMethodType
function isValidVerificationMethodType(type: string): type is VerificationMethodType {
  return ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].includes(type);
}

function parseServices(services: string[]): ServiceEndpoint[] {
  return services.map(service => {
    const [type, serviceEndpoint] = service.split(',');
    return { type, serviceEndpoint };
  });
}

// Update the main function to be exported
export async function main() {
  const [command, ...args] = process.argv.slice(2);
  // console.log('Command:', command);
  // console.log('Args:', args);

  try {
    switch (command) {
      case 'create':
        console.log('Handling create command...');
        await handleCreate(args);
        break;
      case 'resolve':
        await handleResolve(args);
        break;
      case 'update':
        await handleUpdate(args);
        break;
      case 'deactivate':
        await handleDeactivate(args);
        break;
      case 'generate-witness-proof':
        await handleGenerateWitnessProof(args);
        break;
      case 'generate-vm':
        const vm = await generateVerificationMethod('authentication');
        const publicKeyMultibase = vm.publicKeyMultibase;
        const did = `did:key:${publicKeyMultibase}`;
        console.log(JSON.stringify({
          did,
          publicKeyMultibase,
          secretKeyMultibase: vm.secretKeyMultibase
        }, null, 2));
        break;
      case 'help':
        showHelp();
        break;
      default:
        console.error('Unknown command:', command);
        showHelp();
        process.exit(1);
    }
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Only run main if this file is being executed directly
if (process.argv[1] === import.meta.path) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}


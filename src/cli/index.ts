#!/usr/bin/env node

import fs from 'node:fs';
import { dirname } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import type {
  DIDDocument,
  DIDLog,
  ResolutionOptions,
  Service,
  Signer,
  SigningInput,
  SigningOutput,
  Verifier,
  WitnessProofFileEntry,
} from '../index.js';
import {
  createDID,
  deactivateDID,
  resolveDID,
  resolveDIDFromLog,
  signWitnessProofEntries,
  updateDID,
  verifyWitnessProofs,
} from '../index.js';
import { concatBuffers } from '../utils/buffer.js';
import { canonicalizeStrict } from '../utils/canonicalize.js';
import { createHash } from '../utils/crypto.js';
import { MultibaseEncoding, multibaseDecode, multibaseEncode } from '../utils/multiformats.js';
import { parseDidKeyDid } from '../utils/verification-methods.js';
import { deepClone } from '../utils.js';
import { addVerificationMethodToDocument, type VerificationRelationship } from './did-document.js';
import {
  type CliSigningKey,
  getVerificationMethodsFromEnv,
  readLogFromDisk,
  writeLogToDisk,
  writeVerificationMethodToEnv,
} from './persistence.js';

const usage = `
Usage: pnpm cli -- [command] [options]

Commands:
  create     Create a new DID
  resolve    Resolve a DID
  verify-proofs Verify witness proofs for a DID log
  update     Update an existing DID
  deactivate Deactivate an existing DID
  generate-witness-proof Generate witness proofs for a DID version
  generate-vm Generate a new verification method keypair

Options:
  --address [address]       Address for the DID (host, host:port, https://url, or did:webvh form) (required for create)
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
  --witness-file [file]     Path to witness proofs file (optional for resolve, update, deactivate)

  # Options for generate-witness-proof:
  --version-id [id]         The version ID to generate proofs for (required, can be used multiple times)
  --witness-did [did]       Witness DID (did:key) (can be used multiple times)
  --witness-secret [secret] Witness secret key multibase (matches witness-did order)

Examples:
  pnpm cli -- create --address example.com --portable --witness did:key:z6Mk... --witness did:key:z6Mk...
  pnpm cli -- create --address https://example.com --portable
  pnpm cli -- create --address "example.com:3000" --portable
  pnpm cli -- create --address "did:webvh:example.com:3000" --portable
  pnpm cli -- resolve --did did:webvh:123456:example.com
  pnpm cli -- resolve --log ./did.jsonl --witness-file ./did-witness.json
  pnpm cli -- verify-proofs --log ./did.jsonl --witness-file ./did-witness.json
  pnpm cli -- update --log ./did.jsonl --output ./updated-did.jsonl --add-vm keyAgreement --service LinkedDomains,https://example.com
  pnpm cli -- deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
  pnpm cli -- generate-witness-proof --version-id 1-abc123 --witness-did did:key:z6Mk... --witness-secret z1A... --output did-witness.json
  pnpm cli -- generate-witness-proof --version-id 1-abc123 --version-id 2-def456 --witness-did did:key:z6Mk... --witness-secret z1A... --output did-witness.json
  pnpm cli -- generate-vm
`;

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1
  ) {
    super(message);
    this.name = 'CliError';
  }
}

// Add this function at the top with the other constants
function showHelp() {
  console.log(usage);
}

function requirePublicKeyMultibase(value: { publicKeyMultibase?: string }): string {
  if (!value.publicKeyMultibase) throw new Error('Expected verification method to include publicKeyMultibase');
  return value.publicKeyMultibase;
}

function parseExplicitPaths(pathsOption: string | string[] | undefined): string[] | undefined {
  if (!pathsOption) return undefined;

  const rawParts = Array.isArray(pathsOption) ? pathsOption : [pathsOption];
  const paths = rawParts
    .flatMap((part) => part.split(':'))
    .map((part) => part.trim())
    .filter(Boolean);

  return paths.length > 0 ? paths : undefined;
}

async function generateVerificationMethod(): Promise<CliSigningKey> {
  const keyPair = ed25519.keygen();
  const publicKeyBytes = new Uint8Array([0xed, 0x01, ...keyPair.publicKey]);
  // Store seed||publicKey (64 bytes) to stay format-compatible with keys
  // generated by earlier @stablelib/ed25519-based CLI versions.
  const secretKeyBytes = new Uint8Array([0x80, 0x26, ...keyPair.secretKey, ...keyPair.publicKey]);
  const publicKeyMultibase = multibaseEncode(publicKeyBytes, MultibaseEncoding.BASE58_BTC);
  const didKey = `did:key:${publicKeyMultibase}`;
  return {
    id: `${didKey}#${publicKeyMultibase}`,
    type: 'Multikey',
    controller: didKey,
    publicKeyMultibase,
    secretKeyMultibase: multibaseEncode(secretKeyBytes, MultibaseEncoding.BASE58_BTC),
  };
}
class CustomCryptoImplementation implements Signer, Verifier {
  private verificationMethod?: CliSigningKey;

  constructor(verificationMethod?: CliSigningKey) {
    this.verificationMethod = verificationMethod;
  }

  getVerificationMethodId(): string {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
    const publicKeyMultibase = requirePublicKeyMultibase(this.verificationMethod);
    return `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
    if (!this.verificationMethod.secretKeyMultibase) {
      throw new Error('Secret key not set on verification method');
    }
    const { document, proof } = input;
    const dataHash = await createHash(canonicalizeStrict(document));
    const proofHash = await createHash(canonicalizeStrict(proof));
    const message = concatBuffers(proofHash, dataHash);
    const secretKeyMultibase = this.verificationMethod.secretKeyMultibase;
    if (!secretKeyMultibase) {
      throw new Error('Verification method secretKeyMultibase not set');
    }
    const secretKey = multibaseDecode(secretKeyMultibase).bytes.slice(2);
    // Legacy stablelib secrets are seed||publicKey (64 bytes); noble signs with the 32-byte seed.
    const seed = secretKey.length === 64 ? secretKey.slice(0, 32) : secretKey;
    const signature = ed25519.sign(message, seed);
    return {
      proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC),
    };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  }
}

function createCustomCrypto(verificationMethod?: CliSigningKey): Signer & Verifier {
  return new CustomCryptoImplementation(verificationMethod);
}

function getLocalDidLogPath(did: string): string | undefined {
  const parts = did.split(':');
  if (parts.length < 3 || parts[0] !== 'did' || parts[1] !== 'webvh') return undefined;
  const fileIdentifier = parts.slice(4).join(':');
  return `./src/routes/${fileIdentifier || '.well-known'}/did.jsonl`;
}

function readWitnessProofsFile(path: string | undefined): WitnessProofFileEntry[] | undefined {
  if (!path) return undefined;
  return JSON.parse(fs.readFileSync(path, 'utf8')) as WitnessProofFileEntry[];
}

async function resolveControlledDidFromEnv(did: string): Promise<DIDLog | undefined> {
  const verificationMethods = await getVerificationMethodsFromEnv();
  const controlled = verificationMethods.some((vm) => (vm.controller || vm.id?.split('#')[0]) === did);
  if (!controlled) return undefined;

  const path = getLocalDidLogPath(did);
  if (!path) return undefined;
  return readLogFromDisk(path);
}

export async function handleCreate(args: string[]) {
  const options = parseOptions(args);

  const addressInput = options.address as string;

  // Extract optional explicit paths (colon-delimited) from CLI args
  // If provided, these override any paths parsed from address input
  const explicitPaths = parseExplicitPaths(options.paths);

  const output = options.output as string | undefined;
  const portable = options.portable !== undefined;
  const nextKeyHashes = options['next-key-hash'] as string[] | undefined;
  const witnesses = options.witness as string[] | undefined;
  const watchers = options.watcher as string[] | undefined;
  const witnessThreshold = options['witness-threshold']
    ? parseInt(options['witness-threshold'] as string, 10)
    : (witnesses?.length ?? 0);
  const services = options.service ? parseServices(options.service as string[]) : undefined;
  const alsoKnownAs = options['also-known-as'] as string[] | undefined;

  if (!addressInput) {
    throw new CliError('Address is required for create command (use --address)');
  }

  try {
    const authKey = await generateVerificationMethod();
    if (!authKey.publicKeyMultibase) {
      throw new Error('Generated verification method is missing publicKeyMultibase');
    }
    const crypto = createCustomCrypto(authKey);

    const publicKeyMultibase = requirePublicKeyMultibase(authKey);
    const keyId = `{DID}#${publicKeyMultibase.slice(-8)}`;
    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
    };
    addVerificationMethodToDocument(
      didDocument,
      {
        id: keyId,
        type: 'Multikey',
        controller: '{DID}',
        publicKeyMultibase,
      },
      ['authentication', 'assertionMethod']
    );

    if (services) {
      didDocument.service = services;
    }
    if (alsoKnownAs) {
      didDocument.alsoKnownAs = alsoKnownAs;
    }

    const { did, doc, meta, log } = await createDID({
      address: addressInput,
      paths: explicitPaths,
      signer: crypto,
      verifier: crypto,
      updateKeys: [publicKeyMultibase],
      didDocument,
      portable,
      witness: witnesses?.length
        ? {
            witnesses: witnesses.map((witness) => ({ id: witness })),
            threshold: witnessThreshold,
          }
        : undefined,
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
        id: `${did}#${publicKeyMultibase.slice(-8)}`,
      });
      console.log(`DID verification method saved to env`);
    } else {
      // If no output specified, print to console
      console.log('DID Document:', JSON.stringify(doc, null, 2));
      console.log('DID Log:', JSON.stringify(log, null, 2));
    }

    return { did, doc, meta, log };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error creating DID: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function handleResolve(args: string[]) {
  const options = parseOptions(args);
  const didIdentifier = options.did as string;
  const logFile = options.log as string;
  const witnessFile = options['witness-file'] as string | undefined;

  if (!didIdentifier && !logFile) {
    throw new CliError('Either --did or --log is required for resolve command');
  }

  const resolutionOptions: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[]; verifier?: Verifier } = {};
  if (witnessFile) {
    const witnessProofs = JSON.parse(fs.readFileSync(witnessFile, 'utf8'));
    resolutionOptions.witnessProofs = witnessProofs;
  }
  resolutionOptions.verifier = createCustomCrypto();

  try {
    if (logFile) {
      const log = await readLogFromDisk(logFile);
      const resolution = await resolveDIDFromLog(log, resolutionOptions);
      const doc = resolution.didDocument;
      const meta = resolution.didDocumentMetadata;
      const did = doc?.id ?? log[log.length - 1]?.state?.id ?? '';
      if (resolution.didResolutionMetadata.error) {
        throw new CliError(`Resolution error: ${JSON.stringify(resolution.didResolutionMetadata, null, 2)}`);
      }
      console.log('Resolved DID:', did);
      console.log('DID Document:', JSON.stringify(doc, null, 2));
      console.log('Metadata:', JSON.stringify(meta, null, 2));
      return { did, doc, meta };
    } else {
      const resolution = await resolveDID(didIdentifier, {
        ...resolutionOptions,
        resolveControlledDid: resolveControlledDidFromEnv,
      });
      const doc = resolution.didDocument;
      const meta = resolution.didDocumentMetadata;
      const did = doc?.id ?? didIdentifier;
      if (resolution.didResolutionMetadata.error) {
        throw new CliError(`Resolution error: ${JSON.stringify(resolution.didResolutionMetadata, null, 2)}`);
      }
      console.log('Resolved DID:', did);
      console.log('DID Document:', JSON.stringify(doc, null, 2));
      console.log('Metadata:', JSON.stringify(meta, null, 2));
      return { did, doc, meta };
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error resolving DID: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function handleVerifyProofs(args: string[]) {
  const options = parseOptions(args);
  const logFile = options.log as string;
  const witnessFile = options['witness-file'] as string | undefined;

  if (!logFile) {
    throw new CliError('Log file is required for verify-proofs command');
  }
  if (!witnessFile) {
    throw new CliError('Witness file is required for verify-proofs command');
  }

  try {
    const log = await readLogFromDisk(logFile);
    const witnessProofs = readWitnessProofsFile(witnessFile);
    if (!witnessProofs) {
      throw new Error('Witness proofs could not be loaded');
    }

    const result = await verifyWitnessProofs(log, witnessProofs, {
      verifier: createCustomCrypto(),
    });
    console.log(JSON.stringify(result, null, 2));
    // Note: result.verified being false is a successful check with a negative outcome, not an
    // error. It is not thrown as a CliError here; callers (e.g. main()) map it to a non-zero
    // exit code based on the returned result.
    return result;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error verifying witness proofs: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function handleUpdate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options.log as string;
  const output = options.output as string | undefined;
  const witnessProofs = readWitnessProofsFile(options['witness-file'] as string | undefined);
  const witnesses = options.witness as string[] | undefined;
  const witnessThreshold = options['witness-threshold']
    ? parseInt(options['witness-threshold'] as string, 10)
    : undefined;
  const services = options.service ? parseServices(options.service as string[]) : undefined;
  const addVm = options['add-vm'] as VerificationRelationship[] | undefined;
  const alsoKnownAs = options['also-known-as'] as string[] | undefined;
  const updateKey = options['update-key'] as string | undefined;
  const watchers = options.watcher as string[] | undefined;

  if (!logFile) {
    throw new CliError('Log file is required for update command');
  }

  try {
    const log = await readLogFromDisk(logFile);
    const updateResolution = await resolveDIDFromLog(log, {
      verifier: createCustomCrypto(),
      witnessProofs,
    });
    if (updateResolution.didResolutionMetadata.error) {
      throw new Error(`Resolution failed: ${updateResolution.didResolutionMetadata.error}`);
    }
    const meta = updateResolution.didDocumentMetadata;
    const did = updateResolution.didDocument?.id ?? '';
    // console.log('\nCurrent DID:', did);
    // console.log('Current meta:', meta);

    // Get the verification method from environment
    const envVMs = await getVerificationMethodsFromEnv();

    let vm: CliSigningKey | undefined;
    if (updateKey) {
      vm = envVMs.find((candidateVm) => candidateVm.publicKeyMultibase === updateKey);
      if (!vm) {
        throw new Error(`No verification method found for update key: ${updateKey}`);
      }
    } else {
      vm = envVMs.find((candidateVm) => candidateVm.controller === did);
    }

    if (!vm && !updateKey) {
      // Try to find VM by matching public key with current update keys
      vm = envVMs.find((candidateVm) =>
        candidateVm.publicKeyMultibase ? meta.updateKeys.includes(candidateVm.publicKeyMultibase) : false
      );
    }

    if (!vm && !updateKey && envVMs.length > 0) {
      // Fall back to first available VM with warning
      console.warn('Warning: No matching verification method found for DID or update keys. Using first available VM.');
      vm = envVMs[0];
    }

    // console.log('\nFound VM:', vm);

    if (!vm) {
      throw new Error('No verification method found in environment');
    }
    if (!vm.publicKeyMultibase) {
      throw new Error('Verification method missing publicKeyMultibase');
    }

    const vmPublicKeyMultibase = requirePublicKeyMultibase(vm);

    const currentDoc = updateResolution.didDocument;
    if (!currentDoc) {
      throw new Error('Resolved DID document is missing');
    }
    const nextDoc: DIDDocument = deepClone(currentDoc);

    if (addVm && addVm.length > 0) {
      const vmId = `${did}#${vmPublicKeyMultibase.slice(-8)}`;
      addVerificationMethodToDocument(
        nextDoc,
        {
          id: vmId,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: vmPublicKeyMultibase,
        },
        addVm
      );
    }

    if (services !== undefined) {
      nextDoc.service = services;
    }
    if (alsoKnownAs !== undefined) {
      nextDoc.alsoKnownAs = alsoKnownAs;
    }

    const crypto = createCustomCrypto(vm);
    const result = await updateDID({
      log,
      signer: crypto,
      verifier: crypto,
      updateKeys: [vmPublicKeyMultibase],
      didDocument: nextDoc,
      witness: witnesses?.length
        ? {
            witnesses: witnesses.map((witness) => ({ id: witness })),
            threshold: witnessThreshold ?? witnesses.length,
          }
        : undefined,
      watchers: watchers ?? undefined,
      witnessProofs,
    });

    if (output) {
      await writeLogToDisk(output, result.log);
      console.log(`Updated DID log written to ${output}`);
    }

    return result;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error updating DID: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function handleDeactivate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options.log as string;
  const output = options.output as string | undefined;
  const witnessProofs = readWitnessProofsFile(options['witness-file'] as string | undefined);

  if (!logFile) {
    throw new CliError('Log file is required for deactivate command');
  }

  try {
    // Read the current log to get the latest state
    const log = await readLogFromDisk(logFile);
    const deactivateResolution = await resolveDIDFromLog(log, {
      verifier: createCustomCrypto(),
      witnessProofs,
    });
    if (deactivateResolution.didResolutionMetadata.error) {
      throw new Error(`Resolution failed: ${deactivateResolution.didResolutionMetadata.error}`);
    }
    const meta = deactivateResolution.didDocumentMetadata;

    // Get the verification method from environment
    const vms = await getVerificationMethodsFromEnv();
    if (!vms || vms.length === 0) {
      throw new Error('No verification method found in environment');
    }

    // Find VM that matches the current update key
    let vm = vms.find((candidateVm) => candidateVm.publicKeyMultibase === meta.updateKeys[0]);

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
      witnessProofs,
    });

    if (output) {
      await writeLogToDisk(output, result.log);
      console.log(`Deactivated DID log written to ${output}`);
    }

    return result;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error deactivating DID: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function handleGenerateWitnessProof(args: string[]) {
  const options = parseOptions(args);
  const rawVersionIds = options['version-id'];
  const versionIds = Array.isArray(rawVersionIds) ? rawVersionIds : rawVersionIds ? [rawVersionIds] : [];
  const witnessDids = options['witness-did'] as string[] | undefined;
  const witnessSecrets = options['witness-secret'] as string[] | undefined;
  const output = options.output as string;

  if (versionIds.length === 0) {
    throw new CliError('At least one --version-id is required');
  }
  if (!output) {
    throw new CliError('Output file is required');
  }
  if (!witnessDids || !witnessSecrets || witnessDids.length !== witnessSecrets.length) {
    throw new CliError('Must provide matching number of witness DIDs and secrets');
  }

  try {
    const witnessSignersByDid: Record<string, Signer> = {};
    const witnesses: { id: string }[] = [];

    for (let i = 0; i < witnessDids.length; i++) {
      const did = witnessDids[i];
      const secret = witnessSecrets[i];
      const { did: normalizedDid, keyMultibase: publicKeyMultibase } = parseDidKeyDid(did);
      const vm: CliSigningKey = {
        id: `${normalizedDid}#${publicKeyMultibase}`,
        type: 'Multikey',
        controller: normalizedDid,
        publicKeyMultibase,
        secretKeyMultibase: secret,
      };

      witnessSignersByDid[normalizedDid] = createCustomCrypto(vm);
      witnesses.push({ id: normalizedDid });
    }

    const witnessEntries = await signWitnessProofEntries(versionIds, witnesses, witnessSignersByDid);

    const witnessFileContent = witnessEntries.map((entry) => ({
      versionId: entry.versionId,
      proof: entry.proof,
    }));

    fs.writeFileSync(output, JSON.stringify(witnessFileContent, null, 2));
    console.log(`Witness proof file generated at ${output}`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(`Error generating witness proof: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function parseOptions(args: string[]): Record<string, string | string[] | undefined> {
  const options: Record<string, string | string[] | undefined> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        if (
          key === 'witness' ||
          key === 'service' ||
          key === 'also-known-as' ||
          key === 'next-key-hash' ||
          key === 'watcher' ||
          key === 'witness-did' ||
          key === 'witness-secret' ||
          key === 'version-id'
        ) {
          options[key] = options[key] || [];
          (options[key] as string[]).push(args[++i]);
        } else if (key === 'add-vm') {
          options[key] = options[key] || [];
          const value = args[++i];
          if (isValidVerificationMethodType(value)) {
            (options[key] as VerificationRelationship[]).push(value);
          } else {
            throw new CliError(`Invalid verification method type: ${value}`);
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
function isValidVerificationMethodType(type: string): type is VerificationRelationship {
  return ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].includes(
    type
  );
}

function parseServices(services: string[]): Service[] {
  return services.map((service, index) => {
    const [type, serviceEndpoint] = service.split(',');
    return { id: `#service-${index + 1}`, type, serviceEndpoint };
  });
}

// Update the main function to be exported
export async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  // console.log('Command:', command);
  // console.log('Args:', args);

  try {
    switch (command) {
      case 'create':
        console.log('Handling create command...');
        await handleCreate(args);
        return 0;
      case 'resolve':
        await handleResolve(args);
        return 0;
      case 'verify-proofs': {
        const result = await handleVerifyProofs(args);
        return result.verified ? 0 : 1;
      }
      case 'update':
        await handleUpdate(args);
        return 0;
      case 'deactivate':
        await handleDeactivate(args);
        return 0;
      case 'generate-witness-proof':
        await handleGenerateWitnessProof(args);
        return 0;
      case 'generate-vm': {
        const vm = await generateVerificationMethod();
        const publicKeyMultibase = vm.publicKeyMultibase;
        const did = `did:key:${publicKeyMultibase}`;
        console.log(
          JSON.stringify(
            {
              did,
              publicKeyMultibase,
              secretKeyMultibase: vm.secretKeyMultibase,
            },
            null,
            2
          )
        );
        return 0;
      }
      case 'help':
        showHelp();
        return 0;
      default:
        showHelp();
        throw new CliError(`Unknown command: ${command}`);
    }
  } catch (error) {
    if (error instanceof CliError) {
      console.error(error.message);
    } else if (error instanceof Error) {
      console.error(error.stack ?? error.message);
    } else {
      console.error(String(error));
    }
    return error instanceof CliError ? error.exitCode : 1;
  }
}

// Only run main if this file is being executed directly
import { fileURLToPath } from 'node:url';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main()
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error) => {
      console.error('Fatal error:', error);
      process.exitCode = 1;
    });
}

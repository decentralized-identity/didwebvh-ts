import { canonicalize } from 'json-canonicalize';
import { config } from './config';
import { resolveDIDFromLog } from './method';
import type { CreateDIDInterface, DIDDoc, DIDLog, VerificationMethod, WitnessProofFileEntry } from './interfaces';
import { BASE_CONTEXT } from './constants';
import { createBuffer, bufferToString } from './utils/buffer';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './utils/multiformats';
import { createHash } from './utils/crypto';

// Environment detection - treat React Native like a browser, but Bun as Node-like
const isNodeEnvironment = typeof process !== 'undefined'
  && typeof window === 'undefined'
  && !!(process.versions && (process.versions as any).node || (process.versions as any).bun);

// Avoid bundlers including `fs`: hide the specifier from static analyzers
const fsModuleSpecifier = ['node', 'fs'].join(':');
// We'll resolve require dynamically only in Node runtimes; otherwise use dynamic import with a non-literal

let fsModule: any | null = null;
let fsImportPromise: Promise<any> | null = null;

const getFS = async (): Promise<any> => {
  if (!isNodeEnvironment) {
    throw new Error('Filesystem access is not available in this environment (React Native, browser, or failed Node.js import)');
  }
  
  if (fsModule) {
    return fsModule;
  }
  
  if (fsImportPromise) {
    return fsImportPromise;
  }
  
  fsImportPromise = (async () => {
    // Prefer require when present (Node)
    const maybeRequire = (globalThis as any)["require"];
    if (typeof maybeRequire === 'function') {
      try {
        const module = maybeRequire(fsModuleSpecifier);
        fsModule = module;
        return module;
      } catch {}
      try {
        const module = maybeRequire('fs');
        fsModule = module;
        return module;
      } catch {}
    }
    // Fallback to dynamic import (Bun/ESM)
    try {
      const module = await import(fsModuleSpecifier as any);
      fsModule = module as any;
      return module as any;
    } catch {}
    try {
      const module = await import('fs' as any);
      fsModule = module as any;
      return module as any;
    } catch {}
    throw new Error('Filesystem access is not available in this environment (unable to load fs)');
  })();
  
  return fsImportPromise;
};

const toASCII = (domain: string): string => {
  try {
    const scheme = domain.includes('localhost') ? 'http' : 'https';
    return new URL(`${scheme}://${domain}`).hostname;
  } catch {
    return domain;
  }
};

export const readLogFromDisk = async (path: string): Promise<DIDLog> => {
  const fs = await getFS();
  return readLogFromString(fs.readFileSync(path, 'utf8'));
}

export const readLogFromString = (str: string): DIDLog => {
  return str.trim().split('\n').map(l => JSON.parse(l));
}

export const writeLogToDisk = async (path: string, log: DIDLog) => {
  const fs = await getFS();
  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(path, JSON.stringify(log[0]) + '\n');
    
    for (let i = 1; i < log.length; i++) {
      fs.appendFileSync(path, JSON.stringify(log[i]) + '\n');
    }
  } catch (error) {
    console.error('Error writing log to disk:', error);
    throw error;
  }
}

export const maybeWriteTestLog = async (did: string, log: DIDLog) => {
  if (!config.isTestEnvironment) return;
  try {
    const fileSafe = did.replace(/[^a-zA-Z0-9]+/g, '_');
    const path = `./test/logs/${fileSafe}.jsonl`;
    await writeLogToDisk(path, log);
  } catch (error) {
    console.error('Error writing test log:', error);
  }
};

export const writeVerificationMethodToEnv = async (verificationMethod: VerificationMethod) => {
  const envFilePath = process.cwd() + '/.env';
  
  const vmData = {
    id: verificationMethod.id,
    type: verificationMethod.type,
    controller: verificationMethod.controller || '',
    publicKeyMultibase: verificationMethod.publicKeyMultibase,
    secretKeyMultibase: verificationMethod.secretKeyMultibase || ''
  };

  const fs = await getFS();
  try {
    let envContent = '';
    let existingData: any[] = [];
    
    if (fs.existsSync(envFilePath)) {
      envContent = fs.readFileSync(envFilePath, 'utf8');
      const match = envContent.match(/DID_VERIFICATION_METHODS=(.*)/);
      if (match && match[1]) {
        const decodedData = bufferToString(createBuffer(match[1], 'base64'));
        existingData = JSON.parse(decodedData);
        
        // Check if verification method with same ID already exists
        const existingIndex = existingData.findIndex(vm => vm.id === vmData.id);
        if (existingIndex !== -1) {
          // Update existing verification method
          existingData[existingIndex] = vmData;
        } else {
          // Add new verification method
          existingData.push(vmData);
        }
      } else {
        // No existing verification methods, create new array
        existingData = [vmData];
      }
    } else {
      // No .env file exists, create new array
      existingData = [vmData];
    }
    
    const jsonData = JSON.stringify(existingData);
    const encodedData = bufferToString(createBuffer(jsonData), 'base64');
    
    // If DID_VERIFICATION_METHODS already exists, replace it
    if (envContent.includes('DID_VERIFICATION_METHODS=')) {
      envContent = envContent.replace(/DID_VERIFICATION_METHODS=.*\n?/, `DID_VERIFICATION_METHODS=${encodedData}\n`);
    } else {
      // Otherwise append it
      envContent += `DID_VERIFICATION_METHODS=${encodedData}\n`;
    }

    fs.writeFileSync(envFilePath, envContent.trim() + '\n');
    console.log('Verification method written to .env file successfully.');
  } catch (error) {
    console.error('Error writing verification method to .env file:', error);
  }
};

export const clone = (input: any) => JSON.parse(JSON.stringify(input));

export function deepClone(obj: any): any {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (Array.isArray(obj)) return obj.map(item => deepClone(item));
  
  const cloned: any = {};
  for (const [key, value] of Object.entries(obj)) {
    cloned[key] = deepClone(value);
  }
  return cloned;
}

export const getBaseUrl = (id: string) => {
  const parts = id.split(':');
  if (!id.startsWith('did:webvh:') || parts.length < 4) {
    throw new Error(`${id} is not a valid did:webvh identifier`);
  }

  let remainder = decodeURIComponent(parts.slice(3).join('/'));
  const protocol = remainder.includes('localhost') ? 'http' : 'https';

  const [hostPart, ...pathParts] = remainder.split('/');
  let [host, port] = decodeURIComponent(hostPart).split(':');

  host = toASCII(host.normalize("NFC"));

  const normalizedHost = port ? `${host}:${port}` : host;
  const path = pathParts.join('/');

  return `${protocol}://${normalizedHost}${path ? '/' + path : ''}`;
}

export const getFileUrl = (id: string) => {
  const baseUrl = getBaseUrl(id);
  const domainEndIndex = baseUrl.indexOf('/', baseUrl.indexOf('://') + 3);
  
  if (domainEndIndex !== -1) {
    return `${baseUrl}/did.jsonl`;
  }
  return `${baseUrl}/.well-known/did.jsonl`;
}

export async function fetchLogFromIdentifier(identifier: string, controlled: boolean = false): Promise<DIDLog> {
  try {
    if (controlled) {
      const didParts = identifier.split(':');
      const fileIdentifier = didParts.slice(4).join(':');
      const logPath = `./src/routes/${fileIdentifier || '.well-known'}/did.jsonl`;

      try {
        let text: string;
        if (typeof Bun !== 'undefined' && Bun.file) {
          text = (await Bun.file(logPath).text()).trim();
        } else if (isNodeEnvironment) {
          const fs = await getFS();
          text = fs.readFileSync(logPath, 'utf8').trim();
        } else {
          throw new Error('Local log retrieval not supported in this environment');
        }
        if (!text) {
          return [];
        }
        return text.split('\n').map(line => JSON.parse(line));
      } catch (error) {
        throw new Error(`Error reading local DID log: ${error}`);
      }
    }

    const url = getFileUrl(identifier);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const text = (await response.text()).trim();
    if (!text) {
      throw new Error(`DID log not found for ${identifier}`);
    }
    return text.split('\n').map(line => JSON.parse(line));
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

export const createDate = (created?: Date | string) => new Date(created ?? Date.now()).toISOString().slice(0,-5)+'Z';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
}

// Cache for deriveHash operations to avoid redundant computation
const hashCache = new Map<string, string>();

function getCachedHash(input: any): string | undefined {
  try {
    const key = JSON.stringify(input);
    return hashCache.get(key);
  } catch {
    return undefined;
  }
}

function setCachedHash(input: any, hash: string): void {
  try {
    const key = JSON.stringify(input);
    hashCache.set(key, hash);
  } catch {
    // Ignore caching errors
  }
}

export async function deriveHash(input: any): Promise<string> {
  const cached = getCachedHash(input);
  if (cached) {
    return cached;
  }
  
  const data = canonicalize(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  const result = encodeBase58Btc(multihash);
  setCachedHash(input, result);
  return result;
}

export const deriveNextKeyHash = async (input: string): Promise<string> => {
  const hash = await createHash(input);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
}

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{doc: DIDDoc}> => {
  const {controller} = options;
  const all = normalizeVMs(options.verificationMethods, controller);

  // Create the base document
  const doc: DIDDoc = {
    "@context": options.context || BASE_CONTEXT,
    id: controller,
    controller,
  };

  // Add verification methods and relationships from normalizeVMs
  if (all && typeof all === 'object') {
    if (all.verificationMethod) {
      doc.verificationMethod = all.verificationMethod;
    }
    
    if (all.authentication) {
      doc.authentication = all.authentication;
    }
    
    if (all.assertionMethod) {
      doc.assertionMethod = all.assertionMethod;
    }
    
    if (all.keyAgreement) {
      doc.keyAgreement = all.keyAgreement;
    }
    
    if (all.capabilityDelegation) {
      doc.capabilityDelegation = all.capabilityDelegation;
    }
    
    if (all.capabilityInvocation) {
      doc.capabilityInvocation = all.capabilityInvocation;
    }
  }
  
  // Add direct properties from options
  if (options.authentication) {
    doc.authentication = options.authentication;
  }
  
  if (options.assertionMethod) {
    doc.assertionMethod = options.assertionMethod;
  }
  
  if (options.keyAgreement) {
    doc.keyAgreement = options.keyAgreement;
  }
  
  if (options.alsoKnownAs) {
    doc.alsoKnownAs = options.alsoKnownAs;
  }
  
  return {doc};
}

// Helper function to generate a random string (replacement for nanoid)
export const generateRandomId = (length: number = 8): string => {
  const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};

export const createVMID = (vm: VerificationMethod, did: string | null) => {
  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || generateRandomId(8)}`
}

export const normalizeVMs = (verificationMethod: VerificationMethod[] | undefined, did: string | null = null) => {
  const all: any = {
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityDelegation: [],
    capabilityInvocation: []
  };
  
  if (!verificationMethod || verificationMethod.length === 0) {
    return all;
  }
  
  // First collect all VMs
  const vms = verificationMethod.map(vm => ({
    ...vm,
    id: vm.id ?? createVMID(vm, did)
  }));
  all.verificationMethod = vms;

  // Then handle relationships - default to authentication if no purpose is specified
  all.authentication = verificationMethod
    .filter(vm => !vm.purpose || vm.purpose === 'authentication')
    .map(vm => vm.id ?? createVMID(vm, did));

  all.assertionMethod = verificationMethod
    .filter(vm => vm.purpose === 'assertionMethod')
    .map(vm => vm.id ??createVMID(vm, did));

  all.keyAgreement = verificationMethod
    .filter(vm => vm.purpose === 'keyAgreement')
    .map(vm => vm.id ??createVMID(vm, did));

  all.capabilityDelegation = verificationMethod
    .filter(vm => vm.purpose === 'capabilityDelegation')
    .map(vm => vm.id ??createVMID(vm, did));

  all.capabilityInvocation = verificationMethod
    .filter(vm => vm.purpose === 'capabilityInvocation')
    .map(vm => vm.id ?? createVMID(vm, did));

  return all;
};

export const resolveVM = async (vm: string) => {
  try {
    if (vm.startsWith('did:key:')) {
      return {publicKeyMultibase: vm.split('did:key:')[1].split('#')[0]}
    }
    else if (vm.startsWith('did:webvh:')) {
      const url = getFileUrl(vm.split('#')[0]);
      const didLog = await (await fetch(url)).text();
      const logEntries: DIDLog = didLog.trim().split('\n').map(l => JSON.parse(l));
      const {doc} = await resolveDIDFromLog(logEntries, {verificationMethod: vm});
      return findVerificationMethod(doc, vm);
    }
    throw new Error(`Verification method ${vm} not found`);
  } catch (e) {
    throw new Error(`Error resolving VM ${vm}`)
  }
}

export const findVerificationMethod = (doc: any, vmId: string): VerificationMethod | null => {
  // Check in the verificationMethod array
  if (doc.verificationMethod && doc.verificationMethod.some((vm: any) => vm.id === vmId)) {
    return doc.verificationMethod.find((vm: any) => vm.id === vmId);
  }

  // Check in other verification method relationship arrays
  const vmRelationships = ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'];
  for (const relationship of vmRelationships) {
    if (doc[relationship]) {
      if (doc[relationship].some((item: any) => item.id === vmId)) {
        return doc[relationship].find((item: any) => item.id === vmId);
      }
    }
  }

  return null;
}

export async function getActiveDIDs(): Promise<string[]> {
  const activeDIDs: string[] = [];
  
  try {
    for (const vm of config.getVerificationMethods()) {
      const did = vm.controller || vm.id.split('#')[0];
      activeDIDs.push(did);
    }
  } catch (error) {
    console.error('Error processing verification methods:', error);
  }
  
  return activeDIDs;
}

export async function fetchWitnessProofs(did: string): Promise<WitnessProofFileEntry[]> {
  try {
    const url = getFileUrl(did).replace('did.jsonl', 'did-witness.json');
    
    const response = await fetch(url);
    if (!response.ok) {
      return [];
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching witness proofs:', error);
    return [];
  }
}

export function replaceValueInObject(obj: any, searchValue: string, replaceValue: string): any {
  if (typeof obj === 'string') {
    return obj.replaceAll(searchValue, replaceValue);
  }
  if (Array.isArray(obj)) {
    return obj.map(item => replaceValueInObject(item, searchValue, replaceValue));
  }
  if (obj && typeof obj === 'object') {
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = replaceValueInObject(value, searchValue, replaceValue);
    }
    return result;
  }
  return obj;
}
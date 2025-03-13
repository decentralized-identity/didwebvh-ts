import fs from 'node:fs';
import { canonicalize } from 'json-canonicalize';
import { config } from './config';
import { resolveDIDFromLog } from './method';
import type { CreateDIDInterface, DIDDoc, DIDLog, VerificationMethod, WitnessProofFileEntry } from './interfaces';
import { createBuffer, bufferToString } from './utils/buffer';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './utils/multiformats';
import { createHash } from './utils/crypto';

export const readLogFromDisk = (path: string): DIDLog => {
  return readLogFromString(fs.readFileSync(path, 'utf8'));
}

export const readLogFromString = (str: string): DIDLog => {
  return str.trim().split('\n').map(l => JSON.parse(l));
}

export const writeLogToDisk = (path: string, log: DIDLog) => {
  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (!fs.existsSync(dir)) {
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

export const writeVerificationMethodToEnv = (verificationMethod: VerificationMethod) => {
  const envFilePath = process.cwd() + '/.env';
  
  const vmData = {
    id: verificationMethod.id,
    type: verificationMethod.type,
    controller: verificationMethod.controller || '',
    publicKeyMultibase: verificationMethod.publicKeyMultibase,
    secretKeyMultibase: verificationMethod.secretKeyMultibase || ''
  };

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

export const getBaseUrl = (id: string) => {
  const parts = id.split(':');
  if (!id.startsWith('did:webvh:') || parts.length < 4) {
    throw new Error(`${id} is not a valid did:webvh identifier`);
  }
  
  let domain = parts.slice(3).join('/');
  domain = domain.replace(/%2F/g, '/');
  domain = domain.replace(/%3A/g, ':');
  const protocol = domain.includes('localhost') ? 'http' : 'https';
  return `${protocol}://${domain}`;
}

export const getFileUrl = (id: string) => {
  const baseUrl = getBaseUrl(id);
  const url = new URL(baseUrl);
  if (url.pathname !== '/') {
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
        const text = (await Bun.file(logPath).text()).trim();
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

export const deriveHash = async (input: any): Promise<string> => {
  const data = canonicalize(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
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
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1"
    ],
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
    id: createVMID(vm, did)
  }));
  all.verificationMethod = vms;

  // Then handle relationships - default to authentication if no purpose is specified
  all.authentication = verificationMethod
    .filter(vm => !vm.purpose || vm.purpose === 'authentication')
    .map(vm => createVMID(vm, did));

  all.assertionMethod = verificationMethod
    .filter(vm => vm.purpose === 'assertionMethod')
    .map(vm => createVMID(vm, did));

  all.keyAgreement = verificationMethod
    .filter(vm => vm.purpose === 'keyAgreement')
    .map(vm => createVMID(vm, did));

  all.capabilityDelegation = verificationMethod
    .filter(vm => vm.purpose === 'capabilityDelegation')
    .map(vm => createVMID(vm, did));

  all.capabilityInvocation = verificationMethod
    .filter(vm => vm.purpose === 'capabilityInvocation')
    .map(vm => createVMID(vm, did));

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
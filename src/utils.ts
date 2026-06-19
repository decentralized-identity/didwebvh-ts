import { config } from './config';
import { BASE_CONTEXT } from './constants';
import type {
  CreateDIDInterface,
  DIDDoc,
  DIDLog,
  ParsedDidKeyVerificationMethod,
  ServiceEndpoint,
  VerificationMethod,
  WitnessProofFileEntry,
} from './interfaces';
import { resolveDIDFromLog } from './method';
import { bufferToString, createBuffer } from './utils/buffer';
import { canonicalizeStrict } from './utils/canonicalize';
import { createHash } from './utils/crypto';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm, multibaseDecode } from './utils/multiformats';

const DID_KEY_PREFIX = 'did:key:';

function validateDidKeyMultibase(keyMultibase: string): void {
  if (!keyMultibase) {
    throw new Error('Malformed did:key identifier');
  }

  try {
    multibaseDecode(keyMultibase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed did:key identifier: ${message}`);
  }
}

export function parseDidKeyDid(input: string): { did: string; keyMultibase: string } {
  if (typeof input !== 'string') {
    throw new Error('did:key DID must be a string');
  }

  const match = input.match(/^did:key:([^#/?]+)$/);
  if (!match) {
    throw new Error('Malformed did:key DID');
  }

  const keyMultibase = match[1];
  validateDidKeyMultibase(keyMultibase);

  return {
    did: `${DID_KEY_PREFIX}${keyMultibase}`,
    keyMultibase,
  };
}

export function parseDidKeyVerificationMethod(input: string): ParsedDidKeyVerificationMethod {
  if (typeof input !== 'string') {
    throw new Error('did:key verificationMethod must be a string');
  }

  if (input.startsWith('#')) {
    throw new Error('did:key verificationMethod must be an absolute DID URL');
  }

  const match = input.match(/^did:key:([^#/?]+)(?:#([^#/?]+))?$/);
  if (!match) {
    throw new Error('Malformed did:key verificationMethod');
  }

  const parsedDid = parseDidKeyDid(`${DID_KEY_PREFIX}${match[1]}`);
  const fragment = match[2];

  return {
    did: parsedDid.did,
    fragment,
    keyMultibase: parsedDid.keyMultibase,
  };
}

// Canonical address parser for strict parity with didwebvh-rs
interface ParsedAddress {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
}

function isIPAddress(host: string): boolean {
  // Reject IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  // Reject IPv6 (with or without brackets)
  const bare = host.replace(/^\[|\]$/g, '');
  if (/^[0-9a-f:]+$/i.test(bare)) return true;
  return false;
}

function isDoubleEncoded(value: string): boolean {
  // Detect %25 (which is percent-encoded %)
  return value.includes('%25');
}

export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  // Parse did:webvh form
  if (input.startsWith('did:webvh:')) {
    const parts = input.substring(10).split(':');
    if (parts.length < 2) {
      throw new Error('Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain');
    }

    const scid = parts[0];
    const domainPart = parts[1];
    const pathParts = parts.slice(2);

    // Detect double encoding
    if (isDoubleEncoded(domainPart)) {
      throw new Error('Domain is double-encoded (detected %25)');
    }

    // Extract port from domain if %3A-encoded
    let host = domainPart;
    let port: number | undefined;

    if (domainPart.includes('%3A')) {
      const [h, p] = domainPart.split('%3A');
      host = h;
      const portNum = parseInt(p, 10);
      if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
        throw new Error(`Invalid port number: ${p}`);
      }
      port = portNum;
    }

    if (isIPAddress(host)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    return {
      canonicalHost: host,
      canonicalPort: port,
      didDomainComponent: domainPart,
      paths: pathParts.length > 0 ? pathParts : undefined,
    };
  }

  // Parse URL form: HTTPS everywhere, with localhost-only HTTP for local testing.
  if (input.startsWith('https://') || input.startsWith('http://')) {
    try {
      const url = new URL(input);
      if (url.protocol === 'http:' && url.hostname !== 'localhost') {
        throw new Error('HTTP is only allowed for localhost; use HTTPS for non-local hosts');
      }
      const host = url.hostname;
      const port = url.port ? parseInt(url.port, 10) : undefined;

      if (isIPAddress(host)) {
        throw new Error('IP addresses are not allowed as hosts');
      }

      let didDomainComponent = host;
      if (port) {
        didDomainComponent += `%3A${port}`;
      }

      const pathParts: string[] = [];
      if (url.pathname && url.pathname !== '/') {
        url.pathname
          .split('/')
          .filter((p) => p.length > 0)
          .forEach((p) => {
            pathParts.push(p);
          });
      }

      return {
        canonicalHost: host,
        canonicalPort: port,
        didDomainComponent,
        paths: pathParts.length > 0 ? pathParts : undefined,
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (message.includes('not allowed')) throw e;
      throw new Error(`Invalid URL: ${message}`);
    }
  }

  // Parse domain string form (host or host:port)
  // Detect double encoding
  if (isDoubleEncoded(input)) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  let host = input;
  let port: number | undefined;

  // Check if pre-encoded with %3A
  if (input.includes('%3A')) {
    const parts = input.split('%3A');
    if (parts.length !== 2) {
      throw new Error('Invalid pre-encoded port separator');
    }
    host = parts[0];
    const portNum = parseInt(parts[1], 10);
    if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
      throw new Error(`Invalid port number: ${parts[1]}`);
    }
    port = portNum;
  } else if (input.includes(':')) {
    // Raw host:port form
    const parts = input.split(':');
    if (parts.length !== 2) {
      throw new Error('Invalid host:port format');
    }
    host = parts[0];
    const portNum = parseInt(parts[1], 10);
    if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
      throw new Error(`Invalid port number: ${parts[1]}`);
    }
    port = portNum;
  }

  if (isIPAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  let didDomainComponent = host;
  if (port) {
    didDomainComponent += `%3A${port}`;
  }

  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent,
  };
}

type ProcessVersionsLike = { node?: string; bun?: string };

// Environment detection - treat React Native like a browser, but Bun as Node-like
const isNodeEnvironment =
  typeof process !== 'undefined' &&
  typeof window === 'undefined' &&
  !!(
    (process.versions as ProcessVersionsLike | undefined)?.node ||
    (process.versions as ProcessVersionsLike | undefined)?.bun
  );

// Avoid bundlers including `fs`: hide the specifier from static analyzers
const fsModuleSpecifier = ['node', 'fs'].join(':');
// We'll resolve require dynamically only in Node runtimes; otherwise use dynamic import with a non-literal

type FsModule = typeof import('node:fs');
type GlobalRequire = (id: string) => FsModule;

let fsModule: FsModule | null = null;
let fsImportPromise: Promise<FsModule> | null = null;

const getFS = async (): Promise<FsModule> => {
  if (!isNodeEnvironment) {
    throw new Error(
      'Filesystem access is not available in this environment (React Native, browser, or failed Node.js import)'
    );
  }

  if (fsModule) {
    return fsModule;
  }

  if (fsImportPromise) {
    return fsImportPromise;
  }

  fsImportPromise = (async () => {
    // Prefer require when present (Node)
    const maybeRequire = (globalThis as { require?: GlobalRequire }).require;
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
      const module = (await import(fsModuleSpecifier)) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      const module = (await import('node:fs')) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      // biome-ignore lint/style/useNodejsImportProtocol: Compatibility fallback for runtimes/bundlers that reject node: builtins.
      const module = (await import('fs')) as FsModule;
      fsModule = module;
      return module;
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

export const DID_PLACEHOLDER = '{DID}';

export function validateCreateDidDocument(didDocument: DIDDoc): void {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new Error('didDocument must be an object');
  }
  if (typeof didDocument.id !== 'string') {
    throw new Error("didDocument 'id' field must be a string");
  }
  if (!didDocument.id.includes('{SCID}') && !didDocument.id.includes(DID_PLACEHOLDER)) {
    throw new Error("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  }
}

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  const withScid = replaceValueInObject(input, '{SCID}', scid);
  return replaceValueInObject(withScid, DID_PLACEHOLDER, did) as T;
}

export function convertWebvhIdToWebId(id: string): string {
  const parts = id.split(':');
  if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'webvh') {
    throw new Error(`Invalid did:webvh id '${id}'`);
  }
  return `did:web:${parts.slice(3).join(':')}`;
}

/**
 * Returns the host/domain segment of a did:webvh identifier — the segment
 * immediately following the SCID (`did:webvh:{scid}:{domain}...`).
 */
export function getWebvhHost(id: string): string {
  const parts = id.split(':');
  if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'webvh') {
    throw new Error(`Invalid did:webvh id '${id}'`);
  }
  return parts[3];
}

/**
 * Returns the full location of a did:webvh identifier — domain plus any path
 * segments (`did:webvh:{scid}:{domain}:{path}...`), i.e. everything after the
 * SCID. Used to detect whether a DID has moved when portability is disabled.
 */
export function getWebvhLocation(id: string): string {
  const parts = id.split(':');
  if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'webvh') {
    throw new Error(`Invalid did:webvh id '${id}'`);
  }
  return parts.slice(3).join(':');
}

export function enrichAlsoKnownAs(doc: DIDDoc, did: string, opts: { alsoKnownAsWeb?: boolean }): DIDDoc {
  if (doc.alsoKnownAs !== undefined && !Array.isArray(doc.alsoKnownAs)) {
    throw new Error('alsoKnownAs is not an array');
  }

  const aliases = Array.isArray(doc.alsoKnownAs) ? [...doc.alsoKnownAs] : [];
  const addAlias = (alias: string) => {
    if (!aliases.includes(alias)) {
      aliases.push(alias);
    }
  };

  if (opts.alsoKnownAsWeb) {
    addAlias(convertWebvhIdToWebId(did));
  }

  if (aliases.length === 0) {
    return doc;
  }

  return {
    ...doc,
    alsoKnownAs: aliases,
  };
}

export function generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc {
  let webDoc = deepClone(didwebvhDoc);

  const domainPath = didwebvhDid.replace(/^did:webvh:[^:]+:/, '');
  const httpsBase = `https://${decodeURIComponent(domainPath.replace(/:/g, '/'))}/`;

  const existingServiceIds = (webDoc.service ?? []).map((service: ServiceEndpoint) => service.id ?? '');
  const implicitServices: ServiceEndpoint[] = [];

  if (!existingServiceIds.some((id: string) => id.endsWith('#files'))) {
    implicitServices.push({
      id: '#files',
      type: 'relativeRef',
      serviceEndpoint: httpsBase,
    });
  }

  if (!existingServiceIds.some((id: string) => id.endsWith('#whois'))) {
    implicitServices.push({
      '@context': 'https://identity.foundation/linked-vp/contexts/v1',
      id: '#whois',
      type: 'LinkedVerifiablePresentation',
      serviceEndpoint: `${httpsBase}whois.vp`,
    });
  }

  if (implicitServices.length > 0) {
    webDoc = { ...webDoc, service: [...(webDoc.service ?? []), ...implicitServices] };
  }

  const scidPrefix = didwebvhDid.replace(/^did:webvh:([^:]+):.*$/, 'did:webvh:$1:');
  webDoc = replaceValueInObject(webDoc, scidPrefix, 'did:web:');

  const webDid = webDoc.id as string;
  const aliases = (Array.isArray(webDoc.alsoKnownAs) ? [...webDoc.alsoKnownAs] : []).filter(
    (alias: string) => alias !== webDid
  );

  if (!aliases.includes(didwebvhDid)) {
    aliases.push(didwebvhDid);
  }

  return {
    ...webDoc,
    alsoKnownAs: [...new Set(aliases)],
  };
}

export const readLogFromDisk = async (path: string): Promise<DIDLog> => {
  const fs = await getFS();
  return readLogFromString(fs.readFileSync(path, 'utf8'));
};

export const readLogFromString = (str: string): DIDLog => {
  return str
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
};

export const writeLogToDisk = async (path: string, log: DIDLog) => {
  const fs = await getFS();
  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(path, `${JSON.stringify(log[0])}\n`);

    for (let i = 1; i < log.length; i++) {
      fs.appendFileSync(path, `${JSON.stringify(log[i])}\n`);
    }
  } catch (error) {
    console.error('Error writing log to disk:', error);
    throw error;
  }
};

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
  const envFilePath = `${process.cwd()}/.env`;

  const vmData = {
    id: verificationMethod.id,
    type: verificationMethod.type,
    controller: verificationMethod.controller || '',
    publicKeyMultibase: verificationMethod.publicKeyMultibase,
    secretKeyMultibase: verificationMethod.secretKeyMultibase || '',
  };

  const fs = await getFS();
  try {
    let envContent = '';
    let existingData: Array<typeof vmData> = [];

    if (fs.existsSync(envFilePath)) {
      envContent = fs.readFileSync(envFilePath, 'utf8');
      const match = envContent.match(/DID_VERIFICATION_METHODS=(.*)/);
      if (match?.[1]) {
        const decodedData = bufferToString(createBuffer(match[1], 'base64'));
        const parsedData = JSON.parse(decodedData) as unknown;
        existingData = Array.isArray(parsedData) ? (parsedData as Array<typeof vmData>) : [];

        // Check if verification method with same ID already exists
        const existingIndex = existingData.findIndex((vm) => vm.id === vmData.id);
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

    fs.writeFileSync(envFilePath, `${envContent.trim()}\n`);
    console.log('Verification method written to .env file successfully.');
  } catch (error) {
    console.error('Error writing verification method to .env file:', error);
  }
};

export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime()) as T;
  if (Array.isArray(obj)) return obj.map((item) => deepClone(item)) as T;

  const cloned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    cloned[key] = deepClone(value);
  }
  return cloned as T;
}

export const getBaseUrl = (id: string) => {
  const parts = id.split(':');
  if (!id.startsWith('did:webvh:') || parts.length < 4) {
    throw new Error(`${id} is not a valid did:webvh identifier`);
  }

  const remainder = decodeURIComponent(parts.slice(3).join('/'));
  const protocol = remainder.includes('localhost') ? 'http' : 'https';

  const [hostPart, ...pathParts] = remainder.split('/');
  let [host, port] = decodeURIComponent(hostPart).split(':');

  host = toASCII(host.normalize('NFC'));

  const normalizedHost = port ? `${host}:${port}` : host;
  const path = pathParts.join('/');

  return `${protocol}://${normalizedHost}${path ? `/${path}` : ''}`;
};

export const getFileUrl = (id: string) => {
  const baseUrl = getBaseUrl(id);
  const domainEndIndex = baseUrl.indexOf('/', baseUrl.indexOf('://') + 3);

  if (domainEndIndex !== -1) {
    return `${baseUrl}/did.jsonl`;
  }
  return `${baseUrl}/.well-known/did.jsonl`;
};

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
        return text.split('\n').map((line) => JSON.parse(line));
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
    return text.split('\n').map((line) => JSON.parse(line));
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

export const createDate = (created?: Date | string) => `${new Date(created ?? Date.now()).toISOString().slice(0, -5)}Z`;

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
};

// Cache for deriveHash operations to avoid redundant computation
const hashCache = new Map<string, string>();

function getCachedHash(input: unknown): string | undefined {
  try {
    const key = JSON.stringify(input);
    return hashCache.get(key);
  } catch {
    return undefined;
  }
}

function setCachedHash(input: unknown, hash: string): void {
  try {
    const key = JSON.stringify(input);
    hashCache.set(key, hash);
  } catch {
    // Ignore caching errors
  }
}

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  const cached = getCachedHash(input);
  if (cached) {
    return cached;
  }
  const data = canonicalizeStrict(input);
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
};

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{ doc: DIDDoc }> => {
  const { controller } = options;
  const all = normalizeVMs(options.verificationMethods, controller);

  // Create the base document
  const doc: DIDDoc = {
    '@context': options.context || BASE_CONTEXT,
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

  if (options.services) {
    doc.service = options.services;
  }

  return { doc };
};

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
  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || generateRandomId(8)}`;
};

type NormalizedVerificationMethods = Required<
  Pick<
    DIDDoc,
    | 'verificationMethod'
    | 'authentication'
    | 'assertionMethod'
    | 'keyAgreement'
    | 'capabilityDelegation'
    | 'capabilityInvocation'
  >
>;

export const normalizeVMs = (
  verificationMethod: VerificationMethod[] | undefined,
  did: string | null = null
): NormalizedVerificationMethods => {
  const all: NormalizedVerificationMethods = {
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityDelegation: [],
    capabilityInvocation: [],
  };

  if (!verificationMethod || verificationMethod.length === 0) {
    return all;
  }

  // First collect all VMs
  const vms = verificationMethod.map((vm) => ({
    ...vm,
    id: vm.id ?? createVMID(vm, did),
    // Default controller to the DID — required by W3C DID Core §5.2
    controller: vm.controller ?? did,
  }));
  all.verificationMethod = vms as unknown as VerificationMethod[];

  // Then handle relationships - default to authentication if no purpose is specified
  all.authentication = verificationMethod
    .filter((vm) => !vm.purpose || vm.purpose === 'authentication')
    .map((vm) => vm.id ?? createVMID(vm, did));

  all.assertionMethod = verificationMethod
    .filter((vm) => vm.purpose === 'assertionMethod')
    .map((vm) => vm.id ?? createVMID(vm, did));

  all.keyAgreement = verificationMethod
    .filter((vm) => vm.purpose === 'keyAgreement')
    .map((vm) => vm.id ?? createVMID(vm, did));

  all.capabilityDelegation = verificationMethod
    .filter((vm) => vm.purpose === 'capabilityDelegation')
    .map((vm) => vm.id ?? createVMID(vm, did));

  all.capabilityInvocation = verificationMethod
    .filter((vm) => vm.purpose === 'capabilityInvocation')
    .map((vm) => vm.id ?? createVMID(vm, did));

  return all;
};

export const resolveVM = async (vm: string) => {
  try {
    if (vm.startsWith('did:key:')) {
      const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
      return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
    } else if (vm.startsWith('did:webvh:')) {
      const url = getFileUrl(vm.split('#')[0]);
      const didLog = await (await fetch(url)).text();
      const logEntries: DIDLog = didLog
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      const { doc } = await resolveDIDFromLog(logEntries, { verificationMethod: vm });
      return findVerificationMethod(doc, vm);
    }
    throw new Error(`Verification method ${vm} not found`);
  } catch (e) {
    throw new Error(`Error resolving VM ${vm}`);
  }
};

export const findVerificationMethod = (doc: DIDDoc, vmId: string): VerificationMethod | null => {
  // Check in the verificationMethod array
  if (doc.verificationMethod?.some((vm) => vm.id === vmId)) {
    return doc.verificationMethod.find((vm) => vm.id === vmId) ?? null;
  }

  // Check in other verification method relationship arrays
  const vmRelationships = [
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'capabilityInvocation',
    'capabilityDelegation',
  ];
  for (const relationship of vmRelationships) {
    const relationshipValues = doc[relationship as keyof DIDDoc];
    if (
      Array.isArray(relationshipValues) &&
      relationshipValues.some((item) => {
        if (typeof item !== 'object' || item === null) return false;
        const maybeId = (item as { id?: unknown }).id;
        return maybeId === vmId;
      })
    ) {
      const match = relationshipValues.find((item) => {
        if (typeof item !== 'object' || item === null) return false;
        const maybeId = (item as { id?: unknown }).id;
        return maybeId === vmId;
      });
      if (match && typeof match === 'object') {
        return match as VerificationMethod;
      }
    }
  }

  return null;
};

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

export function replaceValueInObject<T>(obj: T, searchValue: string, replaceValue: string): T {
  if (typeof obj === 'string') {
    return obj.replaceAll(searchValue, replaceValue) as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceValueInObject(item, searchValue, replaceValue)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = replaceValueInObject(value, searchValue, replaceValue);
    }
    return result as T;
  }
  return obj;
}

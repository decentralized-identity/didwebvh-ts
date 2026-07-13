import { config } from './config';
import {
  BASE_CONTEXT,
  CONTEXT_LINKED_VP,
  METHOD,
  SERVICE_TYPE_LINKED_VP,
  SERVICE_TYPE_RELATIVE_REF,
} from './constants';
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
import { canonicalizeStrict } from './utils/canonicalize';
import { createHash } from './utils/crypto';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm, multibaseDecode } from './utils/multiformats';

const DID_KEY_PREFIX = 'did:key:';

// did:key parsing helpers

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

  // If fragment is present, it MUST equal the body multibase exactly
  if (fragment && fragment !== parsedDid.keyMultibase) {
    throw new Error(
      `did:key verificationMethod fragment must equal body multibase. ` +
        `Expected fragment '${parsedDid.keyMultibase}' but got '${fragment}'`
    );
  }

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

export interface ParsedDidWebvhIdentifier {
  scid: string;
  didDomainComponent: string;
  paths?: string[];
  locationKey: string;
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

function hasFragmentOrQuery(value: string): boolean {
  return value.includes('#') || value.includes('?');
}

function decodeHostComponent(host: string): string {
  try {
    return decodeURIComponent(host);
  } catch {
    throw new Error(`Invalid percent-encoding in host: ${host}`);
  }
}

function parsePortNumber(rawPort: string): number {
  const portNum = parseInt(rawPort, 10);
  if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
    throw new Error(`Invalid port number: ${rawPort}`);
  }
  return portNum;
}

function toOptionalPaths(pathSegments: string[]): string[] | undefined {
  return pathSegments.length > 0 ? pathSegments : undefined;
}

function toDidDomainComponent(host: string, port?: number): string {
  return port ? `${host}%3A${port}` : host;
}

function toParsedAddress(host: string, port?: number, paths: string[] = []): ParsedAddress {
  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent: toDidDomainComponent(host, port),
    paths: toOptionalPaths(paths),
  };
}

function parseRawHostPort(input: string): { host: string; port?: number } {
  if (!input.includes(':')) {
    return { host: input };
  }

  const parts = input.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid host:port format');
  }

  return {
    host: parts[0],
    port: parsePortNumber(parts[1]),
  };
}

function parseEncodedPortComponent(value: string): { host: string; port?: number } {
  const encodedSeparator = /%3a/i;
  if (!encodedSeparator.test(value)) {
    return { host: value };
  }

  const parts = value.split(encodedSeparator);
  if (parts.length !== 2) {
    throw new Error('Invalid pre-encoded port separator');
  }

  const [host, rawPort] = parts;
  return { host, port: parsePortNumber(rawPort) };
}

export function validateMethodSpecificPathSegments(pathSegments: string[], context: string): void {
  for (const segment of pathSegments) {
    let decodedSegment: string;
    try {
      decodedSegment = decodeURIComponent(segment);
    } catch {
      throw new Error(`${context} contains invalid percent-encoding in path segment '${segment}'`);
    }

    if (decodedSegment === '.' || decodedSegment === '..') {
      throw new Error(`${context} must not contain dot-segments`);
    }

    if (decodedSegment.includes('/')) {
      throw new Error(`${context} must not contain decoded slash within a single path segment`);
    }

    if (decodedSegment.includes('\\')) {
      throw new Error(`${context} must not contain decoded backslash within a path segment`);
    }

    if (decodedSegment.includes('\u0000')) {
      throw new Error(`${context} must not contain decoded NUL character within a path segment`);
    }

    if (decodedSegment !== decodedSegment.trim()) {
      throw new Error(`${context} must not contain leading or trailing whitespace in decoded path segment`);
    }
  }
}

export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  if (hasFragmentOrQuery(input) && !input.startsWith('http://') && !input.startsWith('https://')) {
    throw new Error('Address input must not include query or fragment components');
  }

  // Parse did:webvh form
  if (input.startsWith('did:webvh:')) {
    const parts = input.substring(10).split(':');
    if (parts.length < 2) {
      throw new Error('Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain');
    }

    const domainPart = parts[1];
    const pathParts = parts.slice(2);

    if (hasFragmentOrQuery(domainPart) || pathParts.some((segment) => hasFragmentOrQuery(segment))) {
      throw new Error('did:webvh identifier must not include query or fragment components');
    }

    validateMethodSpecificPathSegments(pathParts, 'did:webvh identifier');

    // Detect double encoding
    if (isDoubleEncoded(domainPart)) {
      throw new Error('Domain is double-encoded (detected %25)');
    }

    // Extract port from domain if %3A-encoded
    const parsedPort = parseEncodedPortComponent(domainPart);
    const host = decodeHostComponent(parsedPort.host);
    const port = parsedPort.port;

    if (isIPAddress(host)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    return toParsedAddress(host, port, pathParts);
  }

  // Parse URL form: HTTPS everywhere.
  if (input.startsWith('https://') || input.startsWith('http://')) {
    try {
      const url = new URL(input);
      if (url.protocol === 'http:') {
        throw new Error('HTTP is not allowed; use HTTPS');
      }
      if (url.hash || url.search) {
        throw new Error('URL input must not include query or fragment components');
      }
      const host = url.hostname;
      const port = url.port ? parseInt(url.port, 10) : undefined;

      if (isIPAddress(host)) {
        throw new Error('IP addresses are not allowed as hosts');
      }

      const pathParts = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];

      validateMethodSpecificPathSegments(pathParts, 'URL pathname');

      return toParsedAddress(host, port, pathParts);
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

  if (hasFragmentOrQuery(input)) {
    throw new Error('Domain input must not include query or fragment components');
  }

  const hostAndPort = /%3a/i.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);
  const host = decodeHostComponent(hostAndPort.host);
  const port = hostAndPort.port;

  if (isIPAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return toParsedAddress(host, port);
}

export function parseDidWebvhIdentifier(did: string, context: string): ParsedDidWebvhIdentifier {
  const parsedAddress = parseCanonicalAddress(did);
  const didParts = did.split(':');

  if (didParts.length < 4 || didParts[0] !== 'did' || didParts[1] !== METHOD) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const scid = didParts[2];
  if (!scid) {
    throw new Error(`${context} must include SCID segment`);
  }

  const locationKey = parsedAddress.paths?.length
    ? `${parsedAddress.didDomainComponent}:${parsedAddress.paths.join(':')}`
    : parsedAddress.didDomainComponent;

  return {
    scid,
    didDomainComponent: parsedAddress.didDomainComponent,
    paths: parsedAddress.paths,
    locationKey,
  };
}

// URL and DID document helper utilities

const toASCII = (domain: string): string => {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
};

export const getBaseUrl = (id: string) => {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  const parsed = parseCanonicalAddress(id);
  const protocol = 'https';
  const host = toASCII(parsed.canonicalHost.normalize('NFC'));
  const normalizedHost = parsed.canonicalPort ? `${host}:${parsed.canonicalPort}` : host;
  const path = parsed.paths?.join('/') ?? '';

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

/**
 * Check if a service with the given fragment exists in the service array.
 * Matches both fragment form (e.g., '#files') and absolute form (e.g., 'did:webvh:...#files').
 */
export function serviceFragmentExists(services: ServiceEndpoint[], fragment: string, did: string): boolean {
  const fragmentForm = `#${fragment}`;
  const absoluteForm = `${did}#${fragment}`;

  return services.some((s: ServiceEndpoint) => {
    const serviceId = s.id || '';
    return serviceId === fragmentForm || serviceId === absoluteForm;
  });
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
      type: SERVICE_TYPE_RELATIVE_REF,
      serviceEndpoint: httpsBase,
    });
  }

  if (!existingServiceIds.some((id: string) => id.endsWith('#whois'))) {
    implicitServices.push({
      '@context': CONTEXT_LINKED_VP,
      id: '#whois',
      type: SERVICE_TYPE_LINKED_VP,
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

export async function fetchLogFromIdentifier(identifier: string, controlled: boolean = false): Promise<DIDLog> {
  const parseDidLogText = (text: string): DIDLog => {
    return text.split('\n').map((line) => JSON.parse(line));
  };

  try {
    if (controlled) {
      const didParts = identifier.split(':');
      const fileIdentifier = didParts.slice(4).join(':');
      const logPath = `./src/routes/${fileIdentifier || '.well-known'}/did.jsonl`;

      try {
        let text: string;
        if (isNodeEnvironment) {
          const fs = await getFS();
          text = fs.readFileSync(logPath, 'utf8').trim();
        } else {
          throw new Error('Local log retrieval not supported in this environment');
        }
        if (!text) {
          return [];
        }
        return parseDidLogText(text);
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
    return parseDidLogText(text);
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

export const createDate = (created?: Date | string) =>
  new Date(created ?? Date.now()).toISOString().replace(/\.\d{1,3}Z$/, 'Z');

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
      if (!doc) {
        throw new Error(`Verification method ${vm} not found`);
      }
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
      const did = vm.controller || vm.id?.split('#')[0];
      if (did) {
        activeDIDs.push(did);
      }
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

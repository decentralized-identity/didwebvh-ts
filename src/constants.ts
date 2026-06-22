export const PLACEHOLDER = '{SCID}';
export const METHOD = 'webvh';
export const BASE_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'];

// Version 1.0 method constants
export const METHOD_VERSION_1_0 = '1.0';
export const METHOD_PROTOCOL_V1_0 = `did:${METHOD}:${METHOD_VERSION_1_0}`;

// Method parameter keys
export const METHOD_PARAMETER_KEYS = {
  scid: 'scid',
  method: 'method',
  portable: 'portable',
  updateKeys: 'updateKeys',
  nextKeyHashes: 'nextKeyHashes',
  witness: 'witness',
  watchers: 'watchers',
  ttl: 'ttl',
} as const;

// Service fragments for implicit services
export enum ServiceFragment {
  Files = 'files',
  Whois = 'whois',
}

// Service type constants
export const SERVICE_TYPE_RELATIVE_REF = 'relativeRef';
export const SERVICE_TYPE_LINKED_VP = 'LinkedVerifiablePresentation';

// Context URLs
export const CONTEXT_LINKED_VP = 'https://identity.foundation/linked-vp/contexts/v1';

// Error type URLs
export const ERROR_TYPE_INVALID_DID = 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID';
export const ERROR_TYPE_NOT_FOUND = 'https://w3id.org/security#NOT_FOUND';

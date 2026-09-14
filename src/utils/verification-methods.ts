import type { DIDDocument, VerificationMethod } from 'did-resolver';
import { DID_KEY_PREFIX, VERIFICATION_RELATIONSHIPS } from '../constants.js';
import type { ParsedDidKeyVerificationMethod } from '../interfaces.js';
import { multibaseDecode } from './multiformats.js';

export function assertNoPrivateVerificationMaterial(didDocument: DIDDocument): void {
  const visit = (value: unknown, path: string): void => {
    if (Array.isArray(value)) {
      for (const [index, item] of value.entries()) {
        visit(item, `${path}[${index}]`);
      }
      return;
    }
    if (typeof value !== 'object' || value === null) {
      return;
    }

    for (const [property, nestedValue] of Object.entries(value)) {
      const propertyPath = `${path}.${property}`;
      if (property === 'secretKeyMultibase' && nestedValue !== undefined) {
        throw new Error(
          `${propertyPath} contains private key material; private key material must not be included in DID documents`
        );
      }
      visit(nestedValue, propertyPath);
    }
  };

  visit(didDocument, 'didDocument');
}

export function assertValidAuthoredVerificationMethods(didDocument: DIDDocument): void {
  const checkVm = (vm: unknown, location: string) => {
    if (typeof vm === 'object' && vm !== null) {
      const candidate = vm as Record<string, unknown>;
      if (
        'id' in candidate ||
        'type' in candidate ||
        'publicKeyMultibase' in candidate ||
        location.startsWith('verificationMethod')
      ) {
        if (typeof candidate.id !== 'string' || candidate.id.trim() === '') {
          throw new Error(`Verification method at ${location} must have a non-empty string 'id'`);
        }
        if (typeof candidate.controller !== 'string' || candidate.controller.trim() === '') {
          throw new Error(`Verification method at ${location} must have an explicit string 'controller'`);
        }
      }
    }
  };

  if (Array.isArray(didDocument.verificationMethod)) {
    didDocument.verificationMethod.forEach((vm, index) => {
      checkVm(vm, `verificationMethod[${index}]`);
    });
  }

  for (const rel of VERIFICATION_RELATIONSHIPS) {
    const relArray = didDocument[rel as keyof DIDDocument];
    if (Array.isArray(relArray)) {
      relArray.forEach((item, index) => {
        if (typeof item === 'object' && item !== null) {
          checkVm(item, `${rel}[${index}]`);
        }
      });
    }
  }
}

export function findVerificationMethod(doc: DIDDocument, vmId: string): VerificationMethod | null {
  const directMatch = doc.verificationMethod?.find((vm) => vm.id === vmId);
  if (directMatch) {
    return directMatch;
  }

  const hasMatchingId = (item: unknown): item is VerificationMethod => {
    if (typeof item !== 'object' || item === null) return false;
    return (item as { id?: unknown }).id === vmId;
  };

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const relationshipValues = doc[relationship as keyof DIDDocument];
    if (Array.isArray(relationshipValues)) {
      const match = relationshipValues.find(hasMatchingId);
      if (match) {
        return match;
      }
    }
  }

  return null;
}

export function validateDidKeyMultibase(keyMultibase: string): void {
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

/** Normalize caller-supplied update keys before hashing or signing a new log entry. */
export function normalizeUpdateKeys(updateKeys: string[]): string[] {
  return updateKeys.map((key, index) => {
    try {
      const { keyMultibase } = key.startsWith(DID_KEY_PREFIX)
        ? parseDidKeyVerificationMethod(key)
        : parseDidKeyDid(`${DID_KEY_PREFIX}${key}`);
      const { bytes } = multibaseDecode(keyMultibase);
      if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
        throw new Error("multiKey doesn't include ed25519 header (0xed01)");
      }
      return keyMultibase;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid updateKeys[${index}]: ${message}`);
    }
  });
}

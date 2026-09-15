import type { DIDDocument, VerificationMethod } from '../index.js';

export type VerificationRelationship =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

const resolveDocumentId = (id: string, did: string): string => (id.startsWith('#') ? `${did}${id}` : id);

const documentIdsEqual = (left: string, right: string, did: string): boolean =>
  resolveDocumentId(left, did) === resolveDocumentId(right, did);

const getVerificationMethodId = (value: unknown): string | undefined => {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }

  const id = (value as { id?: unknown }).id;
  return typeof id === 'string' ? id : undefined;
};

export function addVerificationMethodToDocument(
  didDocument: DIDDocument,
  verificationMethod: VerificationMethod,
  relationships: VerificationRelationship[]
): void {
  const did = didDocument.id;
  if (!did) {
    throw new Error('DID document id is missing');
  }

  const existingVms = Array.isArray(didDocument.verificationMethod) ? [...didDocument.verificationMethod] : [];
  if (!existingVms.some((existing) => documentIdsEqual(existing.id, verificationMethod.id, did))) {
    existingVms.push(verificationMethod);
  }
  didDocument.verificationMethod = existingVms;

  for (const relationship of relationships) {
    const currentRelationship = Array.isArray(didDocument[relationship]) ? [...didDocument[relationship]] : [];
    const alreadyRelated = currentRelationship.some((item) => {
      const id = getVerificationMethodId(item);
      return id !== undefined && documentIdsEqual(id, verificationMethod.id, did);
    });

    if (!alreadyRelated) {
      currentRelationship.push(verificationMethod.id);
    }
    didDocument[relationship] = currentRelationship;
  }
}

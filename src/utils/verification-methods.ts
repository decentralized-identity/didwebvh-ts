import type { VerificationRelationship } from '../constants';
import { DID_KEY_PREFIX, VERIFICATION_RELATIONSHIPS } from '../constants';
import type { DIDDoc, DIDLog, ParsedDidKeyVerificationMethod, VerificationMethod } from '../interfaces';
import { resolveDIDFromLog } from '../method';
import { getFileUrl } from '../utils';
import { multibaseDecode } from './multiformats';

type NormalizedVerificationMethods = Required<Pick<DIDDoc, 'verificationMethod' | VerificationRelationship>>;

export function sanitizeVerificationMethods(
  verificationMethods?: VerificationMethod[]
): VerificationMethod[] | undefined {
  return verificationMethods?.map((vm) => {
    if (vm.secretKeyMultibase) {
      console.warn(
        'Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents'
      );
      const { secretKeyMultibase, ...safeVm } = vm;
      return safeVm;
    }

    return vm;
  });
}

export function createVMID(vm: VerificationMethod, did: string | null): string {
  const randomSuffix = (() => {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < 8; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  })();

  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || randomSuffix}`;
}

export function normalizeVMs(
  verificationMethod: VerificationMethod[] | undefined,
  did: string | null = null
): NormalizedVerificationMethods {
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

  const vms = verificationMethod.map((vm) => ({
    ...vm,
    id: vm.id ?? createVMID(vm, did),
    controller: vm.controller ?? did ?? undefined,
  }));
  all.verificationMethod = vms;

  for (const vm of vms) {
    const relationship = vm.purpose;
    if (!relationship) {
      continue;
    }

    if (VERIFICATION_RELATIONSHIPS.includes(relationship as VerificationRelationship)) {
      all[relationship as VerificationRelationship].push(vm.id);
    }
  }

  return all;
}

export function findVerificationMethod(doc: DIDDoc, vmId: string): VerificationMethod | null {
  const directMatch = doc.verificationMethod?.find((vm) => vm.id === vmId);
  if (directMatch) {
    return directMatch;
  }

  const hasMatchingId = (item: unknown): item is VerificationMethod => {
    if (typeof item !== 'object' || item === null) return false;
    return (item as { id?: unknown }).id === vmId;
  };

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const relationshipValues = doc[relationship as keyof DIDDoc];
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

export async function resolveVM(vm: string): Promise<VerificationMethod | { publicKeyMultibase: string } | null> {
  try {
    if (vm.startsWith('did:key:')) {
      const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
      return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
    }

    if (vm.startsWith('did:webvh:')) {
      const url = getFileUrl(vm.split('#')[0]);
      const didLog = await (await fetch(url)).text();
      const logEntries: DIDLog = didLog
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));

      const { didDocument } = await resolveDIDFromLog(logEntries, {});
      if (!didDocument) {
        throw new Error(`Verification method ${vm} not found`);
      }

      return findVerificationMethod(didDocument as DIDDoc, vm);
    }

    throw new Error(`Verification method ${vm} not found`);
  } catch {
    throw new Error(`Error resolving VM ${vm}`);
  }
}

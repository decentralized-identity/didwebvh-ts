import type { VerificationRelationship } from './constants';
import {
  BASE_CONTEXT,
  CONTEXT_LINKED_VP,
  DID_PLACEHOLDER,
  SCID_PLACEHOLDER,
  SERVICE_TYPE_LINKED_VP,
  SERVICE_TYPE_RELATIVE_REF,
  ServiceFragment,
  VERIFICATION_RELATIONSHIPS,
} from './constants';
import type { DIDDoc, ServiceEndpoint, VerificationMethod } from './interfaces';
import { deepClone, getBaseUrl, replaceValueInObject } from './utils';

type CreateDIDDocOptions = {
  did: string;
  verificationMethods?: VerificationMethod[];
  context?: string | string[] | object | object[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  alsoKnownAs?: string[];
  services?: DIDDoc['service'];
};

type ServiceIdStyle = 'absolute' | 'fragment';

type NormalizedVerificationMethods = Required<Pick<DIDDoc, 'verificationMethod' | VerificationRelationship>>;

export function validateCreateDidDocument(didDocument: DIDDoc): void {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new Error('didDocument must be an object');
  }
  if (typeof didDocument.id !== 'string') {
    throw new Error("didDocument 'id' field must be a string");
  }
  if (!didDocument.id.includes(SCID_PLACEHOLDER) && !didDocument.id.includes(DID_PLACEHOLDER)) {
    throw new Error("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  }
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
    const parts = did.split(':');
    if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'webvh') {
      throw new Error(`Invalid did:webvh id '${did}'`);
    }
    addAlias(`did:web:${parts.slice(3).join(':')}`);
  }

  if (aliases.length === 0) {
    return doc;
  }

  return {
    ...doc,
    alsoKnownAs: aliases,
  };
}

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

export const createVMID = (vm: VerificationMethod, did: string | null) => {
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
};

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
};

export const findVerificationMethod = (doc: DIDDoc, vmId: string): VerificationMethod | null => {
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
};

export const createDIDDoc = async (options: CreateDIDDocOptions): Promise<{ doc: DIDDoc }> => {
  const { did } = options;
  const all = normalizeVMs(options.verificationMethods, did);
  const derivedProperties = ['verificationMethod', ...VERIFICATION_RELATIONSHIPS] as const;
  const directProperties = ['authentication', 'assertionMethod', 'keyAgreement', 'alsoKnownAs'] as const;
  const assignIfPresent = <K extends keyof DIDDoc>(property: K, value: DIDDoc[K] | undefined) => {
    if (Array.isArray(value) && value.length === 0) {
      return;
    }

    if (value) {
      doc[property] = value;
    }
  };

  const doc: DIDDoc = {
    '@context': options.context || BASE_CONTEXT,
    id: did,
    controller: did,
  };

  if (all && typeof all === 'object') {
    for (const property of derivedProperties) {
      assignIfPresent(property, all[property]);
    }
  }

  for (const property of directProperties) {
    assignIfPresent(property, options[property]);
  }

  if (options.services) {
    doc.service = options.services;
  }

  return { doc };
};

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  const withScid = replaceValueInObject(input, '{SCID}', scid);
  return replaceValueInObject(withScid, DID_PLACEHOLDER, did) as T;
}

export function addDefaultDidWebvhServices(
  did: string,
  doc: DIDDoc,
  options: { idStyle?: ServiceIdStyle } = {}
): DIDDoc {
  const services = Array.isArray(doc.service) ? [...doc.service] : [];
  const baseUrl = getBaseUrl(did);
  const baseUrlWithTrailingSlash = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const idStyle = options.idStyle ?? 'absolute';
  const createServiceId = (fragment: ServiceFragment) =>
    idStyle === 'fragment' ? `#${fragment}` : `${did}#${fragment}`;

  let changed = false;
  const hasServiceFragment = (fragment: string) => {
    const fragmentForm = `#${fragment}`;
    const absoluteForm = `${did}#${fragment}`;

    return services.some((service: ServiceEndpoint) => {
      const serviceId = service.id || '';
      return serviceId === fragmentForm || serviceId === absoluteForm;
    });
  };

  if (!hasServiceFragment(ServiceFragment.Files)) {
    services.push({
      id: createServiceId(ServiceFragment.Files),
      type: SERVICE_TYPE_RELATIVE_REF,
      serviceEndpoint: baseUrlWithTrailingSlash,
    });
    changed = true;
  }

  if (!hasServiceFragment(ServiceFragment.Whois)) {
    services.push({
      '@context': CONTEXT_LINKED_VP,
      id: createServiceId(ServiceFragment.Whois),
      type: SERVICE_TYPE_LINKED_VP,
      serviceEndpoint: `${baseUrlWithTrailingSlash}whois.vp`,
    });
    changed = true;
  }

  return changed ? { ...doc, service: services } : doc;
}

export function generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc {
  let webDoc = addDefaultDidWebvhServices(didwebvhDid, deepClone(didwebvhDoc), { idStyle: 'fragment' });

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

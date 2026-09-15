import type { DIDDocument, Service } from 'did-resolver';
import {
  CONTEXT_LINKED_VP,
  DID_PLACEHOLDER,
  SCID_PLACEHOLDER,
  SERVICE_TYPE_LINKED_VP,
  SERVICE_TYPE_RELATIVE_REF,
  ServiceFragment,
} from './constants.js';
import { deepClone, getBaseUrl, replaceValueInObject } from './utils.js';

type ServiceIdStyle = 'absolute' | 'fragment';

export function validateCreateDidDocument(didDocument: DIDDocument): void {
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

export function enrichAlsoKnownAs(doc: DIDDocument, did: string, opts: { alsoKnownAsWeb?: boolean }): DIDDocument {
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

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  const withScid = replaceValueInObject(input, '{SCID}', scid);
  return replaceValueInObject(withScid, DID_PLACEHOLDER, did) as T;
}

export function addDefaultDidWebvhServices(
  did: string,
  doc: DIDDocument,
  options: { idStyle?: ServiceIdStyle } = {}
): DIDDocument {
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

    return services.some((service: Service) => {
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

export function generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDocument): DIDDocument {
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

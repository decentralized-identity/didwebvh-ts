import type { DIDLog, FetchLike, ToASCII, WitnessProofFileEntry } from './interfaces.js';
import { buildDidLogUrl } from './parser.js';

// Version parsing/validation utilities

export function parseAndValidateVersionId(versionId: string, expectedVersionNumber: number) {
  const firstDashIndex = versionId.indexOf('-');
  const lastDashIndex = versionId.lastIndexOf('-');

  if (firstDashIndex === -1 || firstDashIndex !== lastDashIndex) {
    throw new Error(`versionId '${versionId}' must contain exactly one '-' separator`);
  }

  const version = versionId.slice(0, firstDashIndex);
  const entryHash = versionId.slice(firstDashIndex + 1);

  if (!/^\d+$/.test(version)) {
    throw new Error(`versionId '${versionId}' must have a numeric version prefix`);
  }

  if (entryHash.length === 0) {
    throw new Error(`versionId '${versionId}' must have a non-empty hash component`);
  }

  const versionNumber = Number(version);
  if (versionNumber !== expectedVersionNumber) {
    throw new Error(`version '${version}' in log doesn't match expected '${expectedVersionNumber}'.`);
  }

  return { version, versionNumber, entryHash };
}

// URL and filesystem/network log loading

export async function fetchLogFromIdentifier(
  identifier: string,
  fetchFn: FetchLike = fetch,
  toASCII?: ToASCII
): Promise<DIDLog> {
  const parseDidLogText = (text: string): DIDLog => {
    return text.split('\n').map((line) => JSON.parse(line));
  };

  const url = buildDidLogUrl(identifier, toASCII);
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const text = (await response.text()).trim();
  if (!text) {
    throw new Error(`DID log not found for ${identifier}`);
  }
  return parseDidLogText(text);
}

export async function fetchWitnessProofs(
  did: string,
  fetchFn: FetchLike = fetch,
  toASCII?: ToASCII
): Promise<WitnessProofFileEntry[]> {
  const url = buildDidLogUrl(did, toASCII).replace('did.jsonl', 'did-witness.json');

  const response = await fetchFn(url);
  if (!response.ok) {
    if (response.status === 404) {
      return [];
    }

    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return await response.json();
}

// Generic object utilities

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

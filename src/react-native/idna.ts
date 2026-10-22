import { urlToASCII as urlToASCIIWithURL } from '../idna.js';

export type DomainToASCII = (domain: string) => string;

let converter: DomainToASCII | undefined;

export function setDomainToASCII(fn: DomainToASCII | undefined): void {
  converter = fn;
}

export function urlToASCII(host: string): string {
  if (!converter) return urlToASCIIWithURL(host);
  try {
    return converter(host);
  } catch {
    throw new Error('Host must be a valid fully qualified domain');
  }
}

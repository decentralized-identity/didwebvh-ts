import * as tr46 from 'tr46';
import type { ToASCII } from './interfaces.js';

/** Optional IDNA converter for runtimes without a conformant WHATWG URL. */
export const toASCII: ToASCII = (host) => {
  const result = tr46.toASCII(host, {
    checkBidi: true,
    checkJoiners: true,
    checkHyphens: false,
    transitionalProcessing: false,
    verifyDNSLength: true,
  });
  if (result === null) throw new Error('Invalid internationalized domain name');
  return result;
};

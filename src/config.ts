import { base64 } from '@scure/base';
import type { VerificationMethod } from './interfaces';

// Helper to safely access environment variables
const isBrowser = typeof window !== 'undefined';

const getEnvValue = (key: string): string | undefined => {
  if (isBrowser) return undefined;
  try {
    return process?.env?.[key];
  } catch {
    return undefined;
  }
};

export const decodeVerificationMethods = (encoded: string): VerificationMethod[] => {
  try {
    const decoded = new TextDecoder().decode(base64.decode(encoded));
    const parsed = JSON.parse(decoded) as unknown;
    return Array.isArray(parsed) ? (parsed as VerificationMethod[]) : [];
  } catch {
    return [];
  }
};

export const encodeVerificationMethods = (methods: VerificationMethod[]): string => {
  return base64.encode(new TextEncoder().encode(JSON.stringify(methods)));
};

export const getVerificationMethodsFromEnv = (envValue?: string): VerificationMethod[] => {
  if (!envValue) return [];
  return decodeVerificationMethods(envValue);
};

export const config = {
  // Helper functions
  getEnvValue,
  isBrowser,

  // Get verification methods from env
  getVerificationMethods: () => {
    return getVerificationMethodsFromEnv(getEnvValue('DID_VERIFICATION_METHODS'));
  },
};

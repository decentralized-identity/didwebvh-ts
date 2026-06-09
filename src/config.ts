import { bufferToString, createBuffer } from './utils/buffer';

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

export const config = {
  // Helper functions
  getEnvValue,
  isBrowser,

  // Environment checks
  isTestEnvironment: getEnvValue('NODE_ENV') === 'test',

  // Feature flags
  logResolves: getEnvValue('LOG_RESOLVES') === 'true',

  // Get verification methods from env
  getVerificationMethods: () => {
    const encoded = getEnvValue('DID_VERIFICATION_METHODS');
    if (!encoded) return [];
    try {
      const decoded = createBuffer(encoded, 'base64');
      return JSON.parse(bufferToString(decoded));
    } catch {
      return [];
    }
  },
};

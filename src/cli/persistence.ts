import { base64 } from '@scure/base';
import type { DIDLog, VerificationMethod } from '../interfaces';

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

type ProcessVersionsLike = { node?: string; bun?: string };

// Environment detection - treat React Native like a browser, but Bun as Node-like
const isNodeEnvironment =
  typeof process !== 'undefined' &&
  typeof window === 'undefined' &&
  !!(
    (process.versions as ProcessVersionsLike | undefined)?.node ||
    (process.versions as ProcessVersionsLike | undefined)?.bun
  );

// Avoid bundlers including `fs`: hide the specifier from static analyzers
const fsModuleSpecifier = ['node', 'fs'].join(':');
// We'll resolve require dynamically only in Node runtimes; otherwise use dynamic import with a non-literal

type FsModule = typeof import('node:fs');
type GlobalRequire = (id: string) => FsModule;

let fsModule: FsModule | null = null;
let fsImportPromise: Promise<FsModule> | null = null;

const getFS = async (): Promise<FsModule> => {
  if (!isNodeEnvironment) {
    throw new Error(
      'Filesystem access is not available in this environment (React Native, browser, or failed Node.js import)'
    );
  }

  if (fsModule) {
    return fsModule;
  }

  if (fsImportPromise) {
    return fsImportPromise;
  }

  fsImportPromise = (async () => {
    // Prefer require when present (Node)
    const maybeRequire = (globalThis as { require?: GlobalRequire }).require;
    if (typeof maybeRequire === 'function') {
      try {
        const module = maybeRequire(fsModuleSpecifier);
        fsModule = module;
        return module;
      } catch {}
      try {
        const module = maybeRequire('fs');
        fsModule = module;
        return module;
      } catch {}
    }
    // Fallback to dynamic import (Bun/ESM)
    try {
      const module = (await import(fsModuleSpecifier)) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      const module = (await import('node:fs')) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      // biome-ignore lint/style/useNodejsImportProtocol: Compatibility fallback for runtimes/bundlers that reject node: builtins.
      const module = (await import('fs')) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    throw new Error('Filesystem access is not available in this environment (unable to load fs)');
  })();

  return fsImportPromise;
};

function parseDidLogText(text: string): DIDLog {
  return text.split('\n').map((line) => JSON.parse(line));
}

export const readLogFromDisk = async (path: string): Promise<DIDLog> => {
  const fs = await getFS();
  return readLogFromString(fs.readFileSync(path, 'utf8'));
};

export const readLogFromString = (str: string): DIDLog => {
  return parseDidLogText(str.trim());
};

export const writeLogToDisk = async (path: string, log: DIDLog) => {
  const fs = await getFS();
  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(path, `${JSON.stringify(log[0])}\n`);

    for (let i = 1; i < log.length; i++) {
      fs.appendFileSync(path, `${JSON.stringify(log[i])}\n`);
    }
  } catch (error) {
    console.error('Error writing log to disk:', error);
    throw error;
  }
};

export const writeVerificationMethodToEnv = async (verificationMethod: VerificationMethod) => {
  const envFilePath = `${process.cwd()}/.env`;

  const vmData = {
    id: verificationMethod.id,
    type: verificationMethod.type,
    controller: verificationMethod.controller || '',
    publicKeyMultibase: verificationMethod.publicKeyMultibase,
    secretKeyMultibase: verificationMethod.secretKeyMultibase || '',
  };

  const fs = await getFS();
  try {
    let envContent = '';
    let existingData: Array<typeof vmData> = [];

    if (fs.existsSync(envFilePath)) {
      envContent = fs.readFileSync(envFilePath, 'utf8');
      const match = envContent.match(/DID_VERIFICATION_METHODS=(.*)/);
      if (match?.[1]) {
        existingData = decodeVerificationMethods(match[1]) as Array<typeof vmData>;

        // Check if verification method with same ID already exists
        const existingIndex = existingData.findIndex((vm) => vm.id === vmData.id);
        if (existingIndex !== -1) {
          // Update existing verification method
          existingData[existingIndex] = vmData;
        } else {
          // Add new verification method
          existingData.push(vmData);
        }
      } else {
        // No existing verification methods, create new array
        existingData = [vmData];
      }
    } else {
      // No .env file exists, create new array
      existingData = [vmData];
    }

    const encodedData = encodeVerificationMethods(existingData as VerificationMethod[]);

    // If DID_VERIFICATION_METHODS already exists, replace it
    if (envContent.includes('DID_VERIFICATION_METHODS=')) {
      envContent = envContent.replace(/DID_VERIFICATION_METHODS=.*\n?/, `DID_VERIFICATION_METHODS=${encodedData}\n`);
    } else {
      // Otherwise append it
      envContent += `DID_VERIFICATION_METHODS=${encodedData}\n`;
    }

    fs.writeFileSync(envFilePath, `${envContent.trim()}\n`);
    console.log('Verification method written to .env file successfully.');
  } catch (error) {
    console.error('Error writing verification method to .env file:', error);
  }
};

export type VerificationMethodEnvReadOptions = {
  cwd?: string;
  env?: Record<string, string | undefined>;
};

export const getVerificationMethodsFromEnv = async (
  options: VerificationMethodEnvReadOptions = {}
): Promise<VerificationMethod[]> => {
  const env = options.env ?? process.env;
  const fromProcess = env.DID_VERIFICATION_METHODS;
  if (fromProcess) {
    const decoded = decodeVerificationMethods(fromProcess);
    if (decoded.length > 0) return decoded;
  }

  const fs = await getFS();
  const envFilePath = `${options.cwd ?? process.cwd()}/.env`;

  if (!fs.existsSync(envFilePath)) {
    return [];
  }

  try {
    const envContent = fs.readFileSync(envFilePath, 'utf8');
    const match = envContent.match(/^DID_VERIFICATION_METHODS=(.*)$/m);
    if (!match?.[1]) {
      return [];
    }

    return decodeVerificationMethods(match[1]);
  } catch (error) {
    console.error('Error reading verification methods from .env file:', error);
    return [];
  }
};

import { deriveHash } from '../src/utils';
import type { DIDLogEntry, DIDLog } from '../src/interfaces';

export function createMockDIDLog(entries: Partial<DIDLogEntry>[]): DIDLog {
  return entries.map((entry, index) => {
    const versionNumber = index + 1;
    const mockEntry: DIDLogEntry = {
      versionId: entry.versionId || `${versionNumber}-${deriveHash(entry)}`,
      versionTime: entry.versionTime || new Date().toISOString(),
      parameters: entry.parameters || {},
      state: entry.state || {},
      proof: entry.proof || []
    };
    return mockEntry;
  });
}

export const isWitnessServerRunning = async (url: string) => {
  try {
    const response = await fetch(`${url}/health`);
    if (response.ok) {
      return true;
    }
    return false;
  } catch (error) {
    console.error('Witness server is not running');
    return false;
  }
};

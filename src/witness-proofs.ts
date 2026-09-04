import { createDataIntegrityProofTemplate, signDataIntegrityProof } from './cryptography';
import type {
  DataIntegrityProof,
  DataIntegrityProofTemplate,
  DIDLogEntry,
  Signer,
  WitnessEntry,
  WitnessParameterResolution,
  WitnessSigningOptions,
  WitnessSigningResult,
} from './interfaces';
import { multibaseDecode } from './utils/multiformats';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from './utils/verification-methods';

/**
 * Creates a single witness DataIntegrityProof for one `versionId`.
 *
 * @param signer Proof signer callback.
 * @param versionId Target DID log version id.
 * @param verificationMethod Witness verification method DID URL.
 * @param created Optional proof creation time in ISO format.
 * @returns A complete DataIntegrityProof for did-witness processing.
 */
export async function createWitnessProof(
  signer: (
    doc: { versionId: string },
    proofTemplate?: DataIntegrityProofTemplate
  ) => Promise<{ proof: Partial<DataIntegrityProof> }>,
  versionId: string,
  verificationMethod: string,
  created: string = new Date().toISOString()
): Promise<DataIntegrityProof> {
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod,
    created,
    proofPurpose: 'assertionMethod',
  });

  const adaptedSigner: Signer<{ versionId: string }> = {
    getVerificationMethodId: () => verificationMethod,
    sign: async ({ document, proof }): Promise<{ proofValue: string }> => {
      const signedData = await signer(document, proof);
      const proofValue = signedData.proof.proofValue;
      if (!proofValue) {
        throw new Error('Witness proof is missing proofValue');
      }
      return { proofValue };
    },
  };

  return signDataIntegrityProof({ versionId }, proofTemplate, adaptedSigner);
}

/**
 * Signs one did-witness proof entry for a single target `versionId`.
 *
 * The signer map is keyed by witness DID (`did:key:...`).
 *
 * @param options Witness signing options for one target version.
 * @returns A witness proof file entry for the target version.
 */
export async function signWitnessProofEntry(options: WitnessSigningOptions): Promise<WitnessSigningResult> {
  if (!options.versionId) {
    throw new Error('versionId is required');
  }

  const witnessCount = options.witnesses.length;
  if (witnessCount === 0) {
    throw new Error('Witness list cannot be empty');
  }

  const proofs = await Promise.all(
    options.witnesses.map(async (witness) => {
      const { did } = parseDidKeyDid(witness.id);
      const signer = options.witnessSignersByDid[did];

      if (!signer) {
        throw new Error(`Missing witness signer for ${did}`);
      }

      const verificationMethod = signer.getVerificationMethodId();
      const parsedVerificationMethod = parseDidKeyVerificationMethod(verificationMethod);

      if (parsedVerificationMethod.did !== did) {
        throw new Error(`Witness signer verificationMethod DID does not match witness id: ${did}`);
      }

      const proofTemplate = createDataIntegrityProofTemplate({
        verificationMethod,
        created: options.created,
        proofPurpose: 'assertionMethod',
      });

      return signDataIntegrityProof({ versionId: options.versionId }, proofTemplate, signer);
    })
  );

  return {
    versionId: options.versionId,
    proof: proofs,
  };
}

/**
 * Signs did-witness proof entries for multiple target `versionId`s.
 *
 * @param versionIds Target DID log version ids.
 * @param witnesses Witness DID entries used to sign.
 * @param witnessSignersByDid Signer map keyed by witness did:key DID.
 * @param created Optional proof creation time in ISO format.
 * @returns A witness proof file entry per version id.
 */
export async function signWitnessProofEntries(
  versionIds: string[],
  witnesses: WitnessEntry[],
  witnessSignersByDid: Record<string, Signer>,
  created?: string
): Promise<WitnessSigningResult[]> {
  return Promise.all(
    versionIds.map((versionId) =>
      signWitnessProofEntry({
        versionId,
        witnesses,
        witnessSignersByDid,
        created,
      })
    )
  );
}

export function resolveWitnessParameter(parameters: DIDLogEntry['parameters']): WitnessParameterResolution | undefined {
  if ('witness' in parameters) {
    return parameters.witness ?? {};
  }

  if ((parameters as { witnesses?: { id: string }[]; witnessThreshold?: string | number }).witnesses) {
    const legacyParameters = parameters as { witnesses: { id: string }[]; witnessThreshold?: string | number };
    return {
      witnesses: legacyParameters.witnesses,
      threshold: legacyParameters.witnessThreshold || legacyParameters.witnesses.length,
    };
  }

  return undefined;
}

export function normalizeWitnessThreshold(threshold: string | number | undefined | null): number {
  return parseInt((threshold ?? 0).toString(), 10);
}

export function hasActiveWitnessRequirement(
  witness?: WitnessParameterResolution | null
): witness is WitnessParameterResolution {
  if (!witness?.witnesses || witness.witnesses.length === 0) {
    return false;
  }

  const threshold = normalizeWitnessThreshold(witness.threshold);
  return threshold > 0;
}

export function validateWitnessParameter(witness: WitnessParameterResolution): void {
  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  const normalizedThreshold = normalizeWitnessThreshold(witness.threshold);

  if (!witness.threshold || normalizedThreshold < 1 || normalizedThreshold > witness.witnesses.length) {
    throw new Error('Witness threshold must be between 1 and the number of witnesses');
  }

  const ids = new Set<string>();
  for (const w of witness.witnesses) {
    const parsedDid = (() => {
      try {
        return parseDidKeyDid(w.id);
      } catch {
        throw new Error('Witness DIDs must be did:key format');
      }
    })();

    // did:webvh v1.0 requires witness keys to be Ed25519 multikeys.
    const keyBytes = multibaseDecode(parsedDid.keyMultibase).bytes;
    if (keyBytes.length < 2 || keyBytes[0] !== 0xed || keyBytes[1] !== 0x01) {
      throw new Error(`Witness DID key type must be Ed25519 (multicodec 0xed01): ${w.id}`);
    }

    if (ids.has(parsedDid.did)) {
      throw new Error(`Duplicate witness id: ${w.id}`);
    }
    ids.add(parsedDid.did);
  }
}

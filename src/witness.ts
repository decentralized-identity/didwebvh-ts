import type {
  DataIntegrityProof,
  DataIntegrityProofTemplate,
  DIDLogEntry,
  Signer,
  SigningInput,
  Verifier,
  WitnessEntry,
  WitnessParameterResolution,
  WitnessProofFileEntry,
  WitnessSigningOptions,
  WitnessSigningResult,
} from './interfaces';
import { fetchWitnessProofs, parseDidKeyDid, parseDidKeyVerificationMethod, resolveVM } from './utils';
import { concatBuffers } from './utils/buffer';
import { canonicalizeStrict } from './utils/canonicalize';
import { createHash } from './utils/crypto';
import { multibaseDecode } from './utils/multiformats';

function createWitnessProofSigner(signer: Signer) {
  return async (
    document: { versionId: string },
    proofTemplate?: DataIntegrityProofTemplate
  ): Promise<{ proof: Partial<DataIntegrityProof> }> => {
    if (!proofTemplate) {
      throw new Error('Witness proof template is required');
    }

    const signed = await signer.sign({
      document,
      proof: proofTemplate,
    } satisfies SigningInput);

    return {
      proof: {
        verificationMethod: proofTemplate.verificationMethod,
        proofValue: signed.proofValue,
      },
    };
  };
}

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
  const proofTemplate: DataIntegrityProofTemplate = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod,
    created,
    proofPurpose: 'assertionMethod',
  };

  const signedData = await signer({ versionId }, proofTemplate);
  const mergedProof = {
    ...proofTemplate,
    ...signedData.proof,
  };

  // Strip undefined fields to keep the proof JSON-compatible.
  const sanitizedProof = JSON.parse(JSON.stringify(mergedProof)) as Partial<DataIntegrityProof>;

  const verificationMethodValue = mergedProof.verificationMethod;
  if (!verificationMethodValue) {
    throw new Error('Witness proof is missing verificationMethod');
  }
  const proofValue = mergedProof.proofValue;
  if (!proofValue) {
    throw new Error('Witness proof is missing proofValue');
  }

  return {
    id: sanitizedProof.id,
    type: sanitizedProof.type ?? proofTemplate.type,
    cryptosuite: sanitizedProof.cryptosuite ?? proofTemplate.cryptosuite,
    verificationMethod: verificationMethodValue,
    created: sanitizedProof.created ?? proofTemplate.created,
    proofValue,
    proofPurpose: sanitizedProof.proofPurpose ?? proofTemplate.proofPurpose,
  };
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

      return createWitnessProof(
        createWitnessProofSigner(signer),
        options.versionId,
        verificationMethod,
        options.created
      );
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

export function validateWitnessParameter(witness: WitnessParameterResolution): void {
  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  if (
    !witness.threshold ||
    parseInt(witness.threshold.toString(), 10) < 1 ||
    parseInt(witness.threshold.toString(), 10) > witness.witnesses.length
  ) {
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

    if (ids.has(parsedDid.did)) {
      throw new Error(`Duplicate witness id: ${w.id}`);
    }
    ids.add(parsedDid.did);
  }
}

export function countWitnessApprovals(proofs: DataIntegrityProof[], witnesses: WitnessEntry[]): number {
  const processed = new Set<string>();
  const witnessesByDid = new Map(
    witnesses.map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proof of proofs) {
    const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
    const witness = witnessesByDid.get(parsedVerificationMethod.did);
    if (witness) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }
      processed.add(witness.id);
    }
  }

  return processed.size;
}

export async function countVerifiedWitnessApprovals(
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameterResolution,
  verifier?: Verifier
): Promise<number> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let approvals = 0;
  const processedWitnesses = new Set<string>();
  const witnessesByDid = new Map(
    (currentWitness.witnesses ?? []).map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proofSet of witnessProofs) {
    for (const proof of proofSet.proof) {
      try {
        if (proof.type !== 'DataIntegrityProof') {
          throw new Error('Invalid witness proof type');
        }

        if (proof.proofPurpose !== 'assertionMethod') {
          throw new Error('Invalid witness proof purpose');
        }

        if (proof.cryptosuite !== 'eddsa-jcs-2022') {
          throw new Error('Invalid witness proof cryptosuite');
        }

        const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
        const witness = witnessesByDid.get(parsedVerificationMethod.did);
        if (!witness || processedWitnesses.has(witness.id)) {
          continue;
        }

        const vm = await resolveVM(proof.verificationMethod);
        if (!vm?.publicKeyMultibase) {
          throw new Error(`Verification Method ${proof.verificationMethod} not found`);
        }

        const publicKey = multibaseDecode(vm.publicKeyMultibase).bytes;
        if (publicKey.length !== 34) {
          throw new Error(`Invalid public key length ${publicKey.length} (should be 34 bytes)`);
        }

        const { proofValue, ...proofWithoutValue } = proof;

        // Create hashes
        const canonicalizedData = canonicalizeStrict({ versionId: logEntry.versionId });
        const canonicalizedProof = canonicalizeStrict(proofWithoutValue);
        const dataHash = await createHash(canonicalizedData);
        const proofHash = await createHash(canonicalizedProof);
        const input = concatBuffers(proofHash, dataHash);
        const signature = multibaseDecode(proofValue).bytes;

        const verified = await verifier.verify(signature, input, publicKey.slice(2));

        if (!verified) {
          throw new Error('Invalid witness proof signature');
        }

        approvals++;
        processedWitnesses.add(witness.id);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(
          `Ignoring invalid witness proof for version ${proofSet.versionId} ` +
            `(verificationMethod: ${proof.verificationMethod}): ${message}`
        );
      }
    }
  }

  return approvals;
}

export { fetchWitnessProofs };

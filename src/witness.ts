import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import type { DataIntegrityProof, DIDLogEntry, WitnessEntry, WitnessProofFileEntry, Verifier, WitnessParameterResolution } from './interfaces';
import { resolveVM } from "./utils";
import { concatBuffers } from './utils/buffer';
import { fetchWitnessProofs } from './utils';
import { multibaseDecode } from './utils/multiformats';

export async function createWitnessProof(
  signer: (doc: any, proofTemplate?: any) => Promise<{proof: any}>,
  versionId: string
): Promise<DataIntegrityProof> {
  const proofTemplate = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: new Date().toISOString(),
    proofPurpose: "authentication"
  };

  const signedData = await signer({versionId}, proofTemplate);

  return {
    ...proofTemplate,
    ...signedData.proof
  };
}

export function validateWitnessParameter(witness: WitnessParameterResolution): void {
  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  if (!witness.threshold || parseInt(witness.threshold.toString()) < 1 || parseInt(witness.threshold.toString()) > witness.witnesses.length) {
    throw new Error('Witness threshold must be between 1 and the number of witnesses');
  }

  const ids = new Set<string>();
  for (const w of witness.witnesses) {
    if (!w.id.startsWith('did:key:')) {
      throw new Error('Witness DIDs must be did:key format');
    }
    if (ids.has(w.id)) {
      throw new Error(`Duplicate witness id: ${w.id}`);
    }
    ids.add(w.id);
  }
}

export function calculateWitnessWeight(proofs: DataIntegrityProof[], witnesses: WitnessEntry[]): number {
  const processed = new Set<string>();

  for (const proof of proofs) {
    const witness = witnesses.find(w => proof.verificationMethod.startsWith(w.id));
    if (witness) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }
      processed.add(witness.id);
    }
  }

  return processed.size;
}

export async function verifyWitnessProofs(
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameterResolution,
  verifier?: Verifier
): Promise<void> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let approvals = 0;
  const processedWitnesses = new Set<string>();

  // Process each proof set
  for (const proofSet of witnessProofs) {
    // Process each proof in the set
    for (const proof of proofSet.proof) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }

      const witness = currentWitness.witnesses?.find(w => proof.verificationMethod.startsWith(w.id));
      if (!witness) {
        throw new Error('Proof from unauthorized witness');
      }

      if (processedWitnesses.has(witness.id)) {
        continue; // Skip duplicate proofs from same witness
      }

      try {
        // Resolve verification method
        const vm = await resolveVM(proof.verificationMethod);
        if (!vm || !vm.publicKeyMultibase) {
          throw new Error(`Verification Method ${proof.verificationMethod} not found`);
        }

        // Decode public key
        let publicKey: Uint8Array;
        try {
          publicKey = multibaseDecode(vm.publicKeyMultibase).bytes;
        } catch (error: any) {
          throw new Error(`Failed to decode public key: ${error.message}`);
        }
        
        if (publicKey.length !== 34) {
          throw new Error(`Invalid public key length ${publicKey.length} (should be 34 bytes)`);
        }

        // Extract proof value and prepare data for verification
        const { proofValue, ...proofWithoutValue } = proof;
        
        // Create hashes
        const canonicalizedData = canonicalize({versionId: logEntry.versionId});
        const canonicalizedProof = canonicalize(proofWithoutValue);
        
        const dataHash = await createHash(canonicalizedData);
        const proofHash = await createHash(canonicalizedProof);
        
        // Concatenate buffers
        const input = concatBuffers(proofHash, dataHash);

        // Decode signature
        let signature: Uint8Array;
        try {
          signature = multibaseDecode(proofValue).bytes;
        } catch (error: any) {
          throw new Error(`Failed to decode signature: ${error.message}`);
        }

        // Verify signature
        const verified = await verifier.verify(
          signature,
          input,
          publicKey.slice(2)
        );

        if (!verified) {
          throw new Error('Invalid witness proof signature');
        }

        approvals++;
        processedWitnesses.add(witness.id);

      } catch (error: any) {
        throw new Error(`Invalid witness proof: ${error.message}`);
      }
    }
  }

  if (approvals < parseInt(currentWitness.threshold?.toString() ?? '0')) {
    throw new Error(`Witness threshold not met: got ${approvals}, need ${currentWitness.threshold}`);
  }
}

export { fetchWitnessProofs }; 
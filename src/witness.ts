import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import type { DataIntegrityProof, DIDLogEntry, WitnessEntry, WitnessParameter, WitnessProofFileEntry, Verifier } from './interfaces';
import { resolveVM } from "./utils";
import { concatBuffers } from './utils/buffer';
import { fetchWitnessProofs } from './utils';
import { multibaseDecode } from './utils/multiformats';

export function validateWitnessParameter(witness: WitnessParameter): void {
  if (!witness.threshold || witness.threshold < 1) {
    throw new Error('Witness threshold must be at least 1');
  }

  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  for (const w of witness.witnesses) {
    if (!w.id.startsWith('did:key:')) {
      throw new Error('Witness DIDs must be did:key format');
    }
    if (typeof w.weight !== 'number' || w.weight < 1) {
      throw new Error('Witness weight must be a positive number');
    }
  }
}

export function calculateWitnessWeight(proofs: DataIntegrityProof[], witnesses: WitnessEntry[]): number {
  let totalWeight = 0;
  
  for (const proof of proofs) {
    const witness = witnesses.find(w => proof.verificationMethod.startsWith(w.id));
    if (witness) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }
      totalWeight += witness.weight;
    }
  }

  return totalWeight;
}

export async function verifyWitnessProofs(
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameter,
  verifier?: Verifier
): Promise<void> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let totalWeight = 0;
  const processedWitnesses = new Set<string>();

  // Process each proof set sequentially to avoid race conditions
  for (const proofSet of witnessProofs) {
    // Process each proof in the set sequentially
    for (const proof of proofSet.proof) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }

      const witness = currentWitness.witnesses.find(w => proof.verificationMethod.startsWith(w.id));
      if (!witness) {
        throw new Error('Proof from unauthorized witness');
      }

      if (processedWitnesses.has(witness.id)) {
        continue;
      }

      try {
        // Resolve verification method
        const vm = await resolveVM(proof.verificationMethod);
        if (!vm) {
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
        
        // Create hashes sequentially to avoid race conditions
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

        // Implement retry mechanism for verification
        let verified = false;
        const maxRetries = 3;
        
        for (let attempt = 0; attempt < maxRetries; attempt++) {
          try {
            verified = await verifier.verify(
              signature,
              input,
              publicKey.slice(2)
            );
            
            if (verified) break;
            
            // Add a small delay before retrying
            if (attempt < maxRetries - 1) {
              await new Promise(resolve => setTimeout(resolve, 10));
            }
          } catch (verifyError: any) {
            console.error(`Verification attempt ${attempt + 1} failed:`, verifyError);
            
            // Only throw on the last attempt
            if (attempt === maxRetries - 1) {
              throw verifyError;
            }
            
            // Add a small delay before retrying
            await new Promise(resolve => setTimeout(resolve, 10));
          }
        }

        if (!verified) {
          console.error('Signature verification failed:');
          console.error('- Signature:', Buffer.from(signature).toString('hex').substring(0, 30) + '...');
          console.error('- Message:', Buffer.from(input).toString('hex').substring(0, 30) + '...');
          console.error('- Public Key:', Buffer.from(publicKey.slice(2)).toString('hex').substring(0, 30) + '...');
          throw new Error('Invalid witness proof signature');
        }

        totalWeight += witness.weight;
        processedWitnesses.add(witness.id);

      } catch (error: any) {
        throw new Error(`Invalid witness proof: ${error.message}`);
      }
    }
  }

  if (totalWeight < currentWitness.threshold) {
    throw new Error(`Witness threshold not met: got ${totalWeight}, need ${currentWitness.threshold}`);
  }
}

export { fetchWitnessProofs }; 
import { createSCID, deriveNextKeyHash, parseDidKeyVerificationMethod, resolveVM } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import { concatBuffers } from './utils/buffer';
import type { DIDLogEntry, Verifier, WitnessParameterResolution } from './interfaces';
import { validateWitnessParameter } from './witness';
import { multibaseDecode } from "./utils/multiformats";

const isKeyAuthorized = (verificationMethod: string, updateKeys: string[]): boolean => {
  const parsedVerificationMethod = parseDidKeyVerificationMethod(verificationMethod);

  return updateKeys.some((updateKey) => {
    return updateKey === parsedVerificationMethod.keyMultibase;
  });
};

export const documentStateIsValid = async (
  doc: DIDLogEntry,
  updateKeys: string[], 
  witness: WitnessParameterResolution | undefined | null,
  skipWitnessVerification?: boolean,
  verifier?: Verifier
) => {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }
  
  let {proof: proofs, ...rest} = doc;
  if (!proofs) {
    throw new Error('Missing proof in DID log entry');
  }
  if (!Array.isArray(proofs)) {
    proofs = [proofs];
  }

  if (witness && witness.witnesses && witness.witnesses.length > 0) {
    if (!skipWitnessVerification) {
      validateWitnessParameter(witness);
    }
  }

  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];

    if (!proof.verificationMethod.startsWith('did:key:')) {
      throw new Error(`Unsupported verification method for DID log entry authorization: ${proof.verificationMethod}`);
    }

    if (!isKeyAuthorized(proof.verificationMethod, updateKeys)) {
      throw new Error(`Key ${proof.verificationMethod} is not authorized to update.`);
    }
    
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'assertionMethod') {
      throw new Error(`Invalid proof purpose '${proof.proofPurpose}' for DID log entry proof. Expected 'assertionMethod'.`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }

    const vm = await resolveVM(proof.verificationMethod);
    if (!vm || !vm.publicKeyMultibase) {
      throw new Error(`Verification Method ${proof.verificationMethod} not found`);
    }

    const publicKey = multibaseDecode(vm.publicKeyMultibase).bytes;
    if (publicKey[0] !== 0xed || publicKey[1] !== 0x01) {
      throw new Error(`multiKey doesn't include ed25519 header (0xed01)`);
    }

    const {proofValue, ...restProof} = proof;
    const signature = multibaseDecode(proofValue).bytes;
    const dataHash = await createHash(canonicalize(rest));
    const proofHash = await createHash(canonicalize(restProof));
    const input = concatBuffers(proofHash, dataHash);

    const verified = await verifier.verify(
      signature,
      input,
      publicKey.slice(2)
    );
    
    if (!verified) {
      throw new Error(`Proof ${i} failed verification (proofValue: ${proofValue})`);
    }
  }
  return true;
}

export const hashChainValid = (derivedHash: string, logEntryHash: string) => {
  return derivedHash === logEntryHash;
}

export const newKeysAreInNextKeys = async (updateKeys: string[], previousNextKeyHashes: string[]) => {
  if (previousNextKeyHashes.length > 0) {
    for (const key of updateKeys) {
      const keyHash = await deriveNextKeyHash(key);
      if (!previousNextKeyHashes.includes(keyHash)) {
        throw new Error(`Invalid update key ${keyHash}. Not found in nextKeyHashes ${previousNextKeyHashes}`);
      }
    }
  }

  return true;
}

export const scidIsFromHash = async (scid: string, hash: string) => {
  return scid === await createSCID(hash);
}

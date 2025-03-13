import { createSCID, deriveNextKeyHash, resolveVM } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import { config } from './config';
import { concatBuffers } from './utils/buffer';
import { WitnessParameter, Verifier } from './interfaces';
import { validateWitnessParameter } from './witness';
import { multibaseDecode } from "./utils/multiformats";

const isKeyAuthorized = (verificationMethod: string, updateKeys: string[]): boolean => {
  if (config.getEnvValue('IGNORE_ASSERTION_KEY_IS_AUTHORIZED') === 'true') return true;

  if (verificationMethod.startsWith('did:key:')) {
    const keyParts = verificationMethod.split('did:key:')[1].split('#');
    const key = keyParts[0];
    
    const authorized = updateKeys.some(updateKey => {
      let updateKeyPart = updateKey;
      if (updateKey.startsWith('did:key:')) {
        updateKeyPart = updateKey.split('did:key:')[1].split('#')[0];
      }
      
      return updateKeyPart === key;
    });
    
    return authorized;
  }
  return false;
};

const isWitnessAuthorized = (verificationMethod: string, witnesses: string[]): boolean => {
  if (config.getEnvValue('IGNORE_WITNESS_IS_AUTHORIZED') === 'true') return true;

  if (verificationMethod.startsWith('did:webvh:')) {
    const didWithoutFragment = verificationMethod.split('#')[0];
    return witnesses.includes(didWithoutFragment);
  }
  return false;
};

export const documentStateIsValid = async (
  doc: any, 
  updateKeys: string[], 
  witness: WitnessParameter | undefined | null,
  skipWitnessVerification?: boolean,
  verifier?: Verifier
) => {
  if (config.getEnvValue('IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID') === 'true') return true;
  
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }
  
  let {proof: proofs, ...rest} = doc;
  if (!Array.isArray(proofs)) {
    proofs = [proofs];
  }

  if (witness && witness.witnesses.length > 0) {
    if (!skipWitnessVerification) {
      validateWitnessParameter(witness);
    }
  }

  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];

    if (proof.verificationMethod.startsWith('did:key:')) {
      if (!isKeyAuthorized(proof.verificationMethod, updateKeys)) {
        throw new Error(`Key ${proof.verificationMethod} is not authorized to update.`);
      }
    } else if (proof.verificationMethod.startsWith('did:webvh:')) {
      if (witness && witness.witnesses.length > 0 && !isWitnessAuthorized(proof.verificationMethod, witness.witnesses.map((w: {id: string}) => w.id))) {
        throw new Error(`Key ${proof.verificationMethod} is not from an authorized witness.`);
      }
    } else {
      throw new Error(`Unsupported verification method: ${proof.verificationMethod}`);
    }
    
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication' && proof.proofPurpose !== 'assertionMethod') {
      throw new Error(`Unknown proof purpose ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }

    const vm = await resolveVM(proof.verificationMethod);
    if (!vm) {
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
      throw new Error(`Proof ${i} failed verification`);
    }
  }
  return true;
}

export const hashChainValid = (derivedHash: string, logEntryHash: string) => {
  if (config.getEnvValue('IGNORE_ASSERTION_HASH_CHAIN_IS_VALID') === 'true') return true;
  return derivedHash === logEntryHash;
}

export const newKeysAreInNextKeys = async (updateKeys: string[], previousNextKeyHashes: string[]) => {
  if (config.getEnvValue('IGNORE_ASSERTION_NEW_KEYS_ARE_VALID') === 'true') return true;

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
  if (config.getEnvValue('IGNORE_ASSERTION_SCID_IS_FROM_HASH') === 'true') return true;
  return scid === await createSCID(hash);
}

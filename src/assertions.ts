import type { DIDLogEntry, Verifier, WitnessParameterResolution } from './interfaces.js';
import { concatBuffers } from './utils/buffer.js';
import { canonicalizeStrict } from './utils/canonicalize.js';
import { createHash, createSCID, deriveNextKeyHash } from './utils/crypto.js';
import {
  decodeBase58Btc,
  decodeMultihash,
  MultibaseEncoding,
  MultihashAlgorithm,
  multibaseDecode,
} from './utils/multiformats.js';
import { parseDidKeyVerificationMethod } from './utils/verification-methods.js';
import { validateWitnessParameter } from './witness.js';

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

  let { proof: proofs, ...rest } = doc;
  if (!proofs) {
    throw new Error('Missing proof in DID log entry');
  }
  if (!Array.isArray(proofs)) {
    proofs = [proofs];
  }

  if (witness?.witnesses && witness.witnesses.length > 0) {
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
      throw new Error(
        `Invalid proof purpose '${proof.proofPurpose}' for DID log entry proof. Expected 'assertionMethod'.`
      );
    }

    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }

    const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
    const publicKeyMultibase = parsedVerificationMethod?.keyMultibase;
    if (!publicKeyMultibase) {
      throw new Error(`Verification Method ${proof.verificationMethod} not found`);
    }

    const publicKey = multibaseDecode(publicKeyMultibase).bytes;
    if (publicKey[0] !== 0xed || publicKey[1] !== 0x01) {
      throw new Error(`multiKey doesn't include ed25519 header (0xed01)`);
    }

    const { proofValue, ...restProof } = proof;
    const signature = multibaseDecode(proofValue).bytes;
    const dataHash = await createHash(canonicalizeStrict(rest));
    const proofHash = await createHash(canonicalizeStrict(restProof));
    const input = concatBuffers(proofHash, dataHash);

    const verified = await verifier.verify(signature, input, publicKey.slice(2));

    if (!verified) {
      throw new Error(`Proof ${i} failed verification (proofValue: ${proofValue})`);
    }
  }
  return true;
};

export const hashChainIsValid = (derivedHash: string, logEntryHash: string) => {
  return derivedHash === logEntryHash;
};

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
};

export const assertValidNextKeyHashes = (nextKeyHashes: unknown, context = 'nextKeyHashes'): string[] => {
  if (!Array.isArray(nextKeyHashes)) {
    throw new Error(`${context} must be an array of derived pre-rotation key hashes`);
  }

  return nextKeyHashes.map((nextKeyHash, index) => {
    const label = `${context}[${index}]`;
    if (typeof nextKeyHash !== 'string' || nextKeyHash.length === 0) {
      throw new Error(`${label} must be a non-empty derived pre-rotation key hash`);
    }

    if (nextKeyHash.startsWith('did:key:')) {
      throw new Error(
        `${label} must be a derived pre-rotation key hash, not a did:key. Use deriveNextKeyHash() first.`
      );
    }

    try {
      const decodedHash = decodeBase58Btc(nextKeyHash);
      const multihash = decodeMultihash(decodedHash);
      if (multihash.algorithm !== MultihashAlgorithm.SHA2_256 || decodedHash.length !== 34) {
        throw new Error('expected SHA-256 multihash');
      }
      return nextKeyHash;
    } catch (hashError) {
      try {
        const decodedKey = multibaseDecode(nextKeyHash);
        if (
          decodedKey.encoding === MultibaseEncoding.BASE58_BTC &&
          decodedKey.bytes[0] === 0xed &&
          decodedKey.bytes[1] === 0x01
        ) {
          throw new Error(
            `${label} must be a derived pre-rotation key hash, not an Ed25519 multikey. ` +
              'Use deriveNextKeyHash() first.'
          );
        }
      } catch (keyError) {
        if (keyError instanceof Error && keyError.message.includes('Use deriveNextKeyHash() first.')) {
          throw keyError;
        }
      }

      const message = hashError instanceof Error ? hashError.message : String(hashError);
      throw new Error(`${label} must be a base58btc-encoded SHA-256 multihash: ${message}`);
    }
  });
};

/**
 * Validate that SCID uses SHA-256 (0x12) multihash algorithm.
 * Per spec: "SHA-256 [[spec:rfc6234]] (multihash code `0x12`) **only**"
 */
const validateScidAlgorithmIsSha256 = (scid: string): void => {
  try {
    const multihashBytes = decodeBase58Btc(scid);
    const { algorithm } = decodeMultihash(multihashBytes);

    if (algorithm !== MultihashAlgorithm.SHA2_256) {
      throw new Error(`SCID multihash algorithm must be SHA-256 (0x12), but got 0x${algorithm.toString(16)}`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes('SCID multihash algorithm')) {
      throw error;
    }
    throw new Error(`Invalid SCID format: ${error instanceof Error ? error.message : String(error)}`);
  }
};

export const scidIsFromHash = async (scid: string, hash: string) => {
  validateScidAlgorithmIsSha256(scid);
  return scid === (await createSCID(hash));
};

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  createDID,
  type DataIntegrityProofTemplate,
  type DIDDocument,
  defaultVerifier,
  MultibaseEncoding,
  multibaseEncode,
  prepareDataForSigning,
  type Signer,
  type SigningInput,
  verifyWitnessProofs,
  type WitnessProofFileEntry,
} from '../src/index.js';

export const EXAMPLE_DIR = fileURLToPath(new URL('../src/routes/.well-known/', import.meta.url));
export const EXAMPLE_ADDRESS = 'example.com';
export const EXAMPLE_CREATED = '2026-01-01T00:00:00Z';

// Fixed seeds keep the output reproducible. These keys are public example material, never real credentials.
const CONTROLLER_SEED = new Uint8Array(32).fill(1);
const WITNESS_SEED = new Uint8Array(32).fill(2);

interface ExampleKey {
  seed: Uint8Array;
  multikey: string;
  verificationMethodId: string;
}

const exampleKey = (seed: Uint8Array): ExampleKey => {
  const multikey = multibaseEncode(
    new Uint8Array([0xed, 0x01, ...ed25519.getPublicKey(seed)]),
    MultibaseEncoding.BASE58_BTC
  );
  return { seed, multikey, verificationMethodId: `did:key:${multikey}#${multikey}` };
};

const sign = async (key: ExampleKey, document: unknown, proof: DataIntegrityProofTemplate): Promise<string> => {
  const message = await prepareDataForSigning(document, proof);
  return multibaseEncode(ed25519.sign(message, key.seed), MultibaseEncoding.BASE58_BTC);
};

const exampleSigner = (key: ExampleKey): Signer => ({
  getVerificationMethodId: () => key.verificationMethodId,
  sign: async ({ document, proof }: SigningInput) => ({ proofValue: await sign(key, document, proof) }),
});

/**
 * Builds the example DID files served from `src/routes/.well-known/`, keyed by file name.
 */
export async function generateExampleFiles(): Promise<Record<string, string>> {
  const controller = exampleKey(CONTROLLER_SEED);
  const witness = exampleKey(WITNESS_SEED);
  const didDocument: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: '{DID}',
    controller: '{DID}',
    verificationMethod: [
      { id: '{DID}#key-1', type: 'Multikey', controller: '{DID}', publicKeyMultibase: controller.multikey },
    ],
    authentication: ['{DID}#key-1'],
    assertionMethod: ['{DID}#key-1'],
  };

  const created = await createDID({
    address: EXAMPLE_ADDRESS,
    signer: exampleSigner(controller),
    verifier: defaultVerifier,
    updateKeys: [controller.multikey],
    didDocument,
    alsoKnownAsWeb: true,
    witness: { witnesses: [{ id: `did:key:${witness.multikey}` }], threshold: 1 },
    created: EXAMPLE_CREATED,
  });

  // signWitnessProofEntry stamps proofs with the current time, so the witness proof is
  // built here with a fixed `created` and checked with verifyWitnessProofs below.
  const versionId = created.log[0].versionId;
  const proofTemplate: DataIntegrityProofTemplate = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: witness.verificationMethodId,
    created: EXAMPLE_CREATED,
    proofPurpose: 'assertionMethod',
  };
  const witnessProofs: WitnessProofFileEntry[] = [
    {
      versionId,
      proof: [
        {
          type: proofTemplate.type,
          cryptosuite: proofTemplate.cryptosuite,
          verificationMethod: proofTemplate.verificationMethod,
          created: proofTemplate.created,
          proofValue: await sign(witness, { versionId }, proofTemplate),
          proofPurpose: proofTemplate.proofPurpose,
        },
      ],
    },
  ];

  const verification = await verifyWitnessProofs({ log: created.log, witnessProofs, verifier: defaultVerifier });
  if (!verification.verified) {
    throw new Error('Generated example witness proof does not satisfy the witness requirement');
  }
  if (!created.webDoc) {
    throw new Error('createDID did not return the parallel did:web document');
  }

  return {
    'did.jsonl': created.log.map((entry) => `${JSON.stringify(entry)}\n`).join(''),
    'did.json': `${JSON.stringify(created.webDoc, null, 2)}\n`,
    'did-witness.json': `${JSON.stringify(witnessProofs, null, 2)}\n`,
  };
}

async function main() {
  const files = await generateExampleFiles();
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(EXAMPLE_DIR, name), content);
    console.log(`Wrote ${join(EXAMPLE_DIR, name)}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main().catch((err) => {
    console.error(`ERROR: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

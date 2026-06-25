import { verify as ed25519Verify } from '@stablelib/ed25519';
import { Elysia } from 'elysia';
import { AbstractCrypto, resolveDID } from '../src';
import type { DIDDoc, SigningInput, SigningOutput, Verifier } from '../src/types';

class ElysiaVerifier extends AbstractCrypto implements Verifier {
  constructor(
    public readonly verificationMethod: {
      id: string;
      controller: string;
      type: string;
      publicKeyMultibase: string;
      secretKeyMultibase: string;
    }
  ) {
    super({ verificationMethod });
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    throw new Error('Not implemented');
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519Verify(publicKey, message, signature);
    } catch (error) {
      console.error('Ed25519 verification error:', error);
      return false;
    }
  }
}

const createElysiaVerifier = () => {
  return new ElysiaVerifier({
    id: 'did:example:123#key-1',
    controller: 'did:example:123',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: `z123`,
    secretKeyMultibase: `z123`,
  });
};

const elysiaVerifier = createElysiaVerifier();

const WELL_KNOWN_ALLOW_LIST = ['did.jsonl'];

// Helper function to map DID resolution errors to HTTP status codes
const getStatusCodeFromError = (errorType?: string): number => {
  switch (errorType) {
    case 'invalidDid':
    case 'invalidDidUrl':
      return 400;
    case 'notFound':
      return 404;
    case 'representationNotSupported':
      return 406;
    default:
      return 500;
  }
};

const getFile = async ({
  params: { path, file },
  isRemote = false,
  didDocument,
}: {
  params: { path: string; file: string };
  isRemote?: boolean;
  didDocument?: DIDDoc;
}) => {
  try {
    if (isRemote) {
      let serviceEndpoint;

      if (file === 'whois') {
        const whoisService = didDocument?.service?.find((s: any) => s.id === '#whois');

        if (whoisService?.serviceEndpoint) {
          serviceEndpoint = whoisService.serviceEndpoint;
        }
      } else {
        const filesService = didDocument?.service?.find((s: any) => s.id === '#files');

        if (filesService?.serviceEndpoint) {
          serviceEndpoint = filesService.serviceEndpoint;
        }
      }

      if (!serviceEndpoint) {
        const cleanDomain = path.replace('.well-known/', '');
        serviceEndpoint = `https://${cleanDomain}`;

        if (file === 'whois') {
          serviceEndpoint = `${serviceEndpoint}/whois.vp`;
        }
      }

      serviceEndpoint = serviceEndpoint.replace(/\/$/, '');
      const url = file === 'whois' ? serviceEndpoint : `${serviceEndpoint}/${file}`;

      const response = await fetch(url);
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Error 404: Not Found');
        }
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }
      return response.text();
    }

    if (file === 'whois') {
      file = 'whois.vp';
    }

    const filePath = WELL_KNOWN_ALLOW_LIST.some((f) => f === file)
      ? `./src/routes/.well-known/${file}`
      : path
        ? `./src/routes/${path}/${file}`
        : `./src/routes/${file}`;

    return await Bun.file(filePath).text();
  } catch (e: unknown) {
    console.error(e);
    throw new Error(`Failed to resolve File: ${e instanceof Error ? e.message : String(e)}`);
  }
};

const port = Number(process.env.PORT ?? 3010);

const app = new Elysia()
  .get('/health', () => 'ok')
  .get('/resolve/:id', async ({ params, query, set }) => {
    try {
      const id = params.id;
      if (!id) {
        set.status = 400;
        return { error: 'No id provided' };
      }

      const [didPart, ...pathParts] = id.split('/');
      if (pathParts.length === 0) {
        const options = {
          versionNumber: query?.versionNumber ? parseInt(query.versionNumber as string, 10) : undefined,
          versionId: query?.versionId as string,
          versionTime: query?.versionTime ? new Date(query.versionTime as string) : undefined,
          verifier: elysiaVerifier,
        };

        console.log(`Resolving DID ${didPart}`);
        const result = await resolveDID(didPart, options);

        // Check for error in resolution metadata and set appropriate status code
        if (result.didResolutionMetadata?.error) {
          set.status = getStatusCodeFromError(result.didResolutionMetadata.error);
        }

        return result;
      }

      const resolution = await resolveDID(didPart, { verifier: elysiaVerifier });
      // Only bail when there is no usable document. A valid earlier version can
      // be returned alongside a warning-level error, so still serve files in that case.
      if (resolution.didResolutionMetadata?.error && !resolution.didDocument) {
        set.status = getStatusCodeFromError(resolution.didResolutionMetadata.error);
        return {
          error: 'Resolution failed',
          details: resolution.didResolutionMetadata.error,
        };
      }
      const did = resolution.didDocument?.id ?? '';
      const doc = (resolution.didDocument as DIDDoc | null) ?? undefined;
      const controlled = Boolean((resolution.didResolutionMetadata as { controlled?: boolean }).controlled);

      const didParts = did.split(':');
      const domain = didParts[didParts.length - 1];
      const fileIdentifier = didParts[didParts.length - 2];

      const fileContent = await getFile({
        params: {
          path: !controlled ? domain : fileIdentifier,
          file: pathParts.join('/'),
        },
        isRemote: !controlled,
        didDocument: doc,
      });

      return fileContent;
    } catch (error: unknown) {
      set.status = 500;
      return {
        error: 'Resolution failed',
        details: error instanceof Error ? error.message : String(error),
      };
    }
  })
  .listen(port);

console.log(`Elysia resolver is running at http://localhost:${app.server?.port ?? port}`);

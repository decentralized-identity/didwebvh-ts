import { Elysia } from 'elysia'
import { resolveDID } from 'didwebvh-ts';
import type { DIDDoc, Verifier } from '../../../src/interfaces';

// Define a simple verifier implementation
class DefaultVerifier implements Verifier {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // This is a placeholder implementation that logs verification attempts
    // In a production environment, you would use a proper cryptographic library
    console.log('Verifying signature with DefaultVerifier');
    console.log(`Signature: ${Buffer.from(signature).toString('hex').substring(0, 20)}...`);
    console.log(`Message: ${Buffer.from(message).toString('hex').substring(0, 20)}...`);
    console.log(`Public Key: ${Buffer.from(publicKey).toString('hex').substring(0, 20)}...`);
    
    // For demonstration purposes, always return true
    // In a real implementation, you would actually verify the signature
    return true;
  }
}

// Create an instance of the default verifier
const defaultVerifier = new DefaultVerifier();

const WELL_KNOWN_ALLOW_LIST = ['did.jsonl'];

export const getFile = async ({
  params: {path, file}, 
  isRemote = false,
  didDocument
}: {
  params: {path: string; file: string}, 
  isRemote?: boolean,
  didDocument?: DIDDoc
}) => {
  try {
    if (isRemote) {
      let serviceEndpoint;
      
      if (file === 'whois') {
        const whoisService = didDocument?.service?.find(
          (s: any) => s.id === '#whois'
        );
        
        if (whoisService?.serviceEndpoint) {
          serviceEndpoint = whoisService.serviceEndpoint;
        }
      } else {
        const filesService = didDocument?.service?.find(
          (s: any) => s.id === '#files'
        );
        
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
    const filePath = WELL_KNOWN_ALLOW_LIST.some(f => f === file) ? `./src/routes/.well-known/${file}` : path ? `./src/routes/${path}/${file}` : `./src/routes/${file}`
    return await Bun.file(filePath).text();
  } catch (e: unknown) {
    console.error(e);
    return new Response(JSON.stringify({
      error: 'Failed to resolve File',
      details: e instanceof Error ? e.message : String(e)
    }), {status: 404});
  }
}

const app = new Elysia()
  .get('/health', 'ok')
  .get('/resolve/:id', async ({ params: { id }, query }) => {
    try {
      if (!id) {
        throw new Error('No id provided');
      }

      const [didPart, ...pathParts] = id.split('/');
      if (pathParts.length === 0) {
        const options = {
          versionNumber: query.versionNumber ? parseInt(query.versionNumber as string) : undefined,
          versionId: query.versionId as string,
          versionTime: query.versionTime ? new Date(query.versionTime as string) : undefined,
          verificationMethod: query.verificationMethod as string,
          // Pass the default verifier to the resolveDID function
          verifier: defaultVerifier
        };
        
        console.log(`Resolving DID ${didPart} with default verifier`);
        return await resolveDID(didPart, options);
      }
      
      // For path-based resolution, also use the default verifier
      const {did, doc, controlled} = await resolveDID(didPart, { verifier: defaultVerifier });
      
      const didParts = did.split(':');
      const domain = didParts[didParts.length - 1];
      const fileIdentifier = didParts[didParts.length - 2];
      
      return await getFile({
        params: {
          path: !controlled ? domain : fileIdentifier,
          file: pathParts.join('/')
        },
        isRemote: !controlled,
        didDocument: doc
      });
    } catch (error: unknown) {
      console.error('Error resolving identifier:', error);
      return new Response(JSON.stringify({
        error: 'Resolution failed',
        details: error instanceof Error ? error.message : String(error)
      }), {status: 400});
    }
  })
  .get('/resolve/:id/*', async ({ params }) => {
    const pathParts = params['*'].split('/');
    return await getFile({
      params: {
        path: pathParts.slice(0, -1).join('/'),
        file: pathParts[pathParts.length - 1]
      },
      isRemote: false
    });
  })
  .get('/.well-known/*', async ({ params }) => {
    const file = params['*'];
    return await getFile({
      params: {
        path: '.well-known',
        file
      },
      isRemote: false
    });
  })

// Get port from environment or use default
const port = process.env.PORT ? parseInt(process.env.PORT) : 8000;

// Log active DIDs when server starts
app.onStart(async () => {
  console.log('\n=== Using Default Verifier ===');
  console.log('All DID resolutions will use the default verifier implementation');
  console.log('==============================\n');
});

console.log(`🔍 Resolver is running at http://localhost:${port}`);
app.listen(port);

import express, { type Request, type Response } from 'express';
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

const app = express();
const port = process.env.PORT ? parseInt(process.env.PORT) : 8000;

const WELL_KNOWN_ALLOW_LIST = ['did.jsonl'];

// Helper function to get file content
const getFile = async ({
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
    throw new Error(`Failed to resolve File: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.send('ok');
});

// DID resolution endpoint
app.get('/resolve/:id', async (req: Request, res: Response) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({
        error: 'No id provided'
      });
    }

    const [didPart, ...pathParts] = id.split('/');
    if (pathParts.length === 0) {
      const options = {
        versionNumber: req.query.versionNumber ? parseInt(req.query.versionNumber as string) : undefined,
        versionId: req.query.versionId as string,
        versionTime: req.query.versionTime ? new Date(req.query.versionTime as string) : undefined,
        verificationMethod: req.query.verificationMethod as string,
        // Pass the default verifier to the resolveDID function
        verifier: defaultVerifier
      };
      
      console.log(`Resolving DID ${didPart} with default verifier`);
      const result = await resolveDID(didPart, options);
      return res.json(result);
    }
    
    // For path-based resolution, also use the default verifier
    const {did, doc, controlled} = await resolveDID(didPart, { verifier: defaultVerifier });
    
    const didParts = did.split(':');
    const domain = didParts[didParts.length - 1];
    const fileIdentifier = didParts[didParts.length - 2];
    
    const fileContent = await getFile({
      params: {
        path: !controlled ? domain : fileIdentifier,
        file: pathParts.join('/')
      },
      isRemote: !controlled,
      didDocument: doc
    });
    
    res.send(fileContent);
  } catch (error: unknown) {
    console.error('Error resolving identifier:', error);
    res.status(400).json({
      error: 'Resolution failed',
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

// Wildcard path resolution
app.get('/resolve/:id/*', async (req: Request, res: Response) => {
  try {
    const pathParts = req.params[0].split('/');
    const fileContent = await getFile({
      params: {
        path: pathParts.slice(0, -1).join('/'),
        file: pathParts[pathParts.length - 1]
      },
      isRemote: false
    });
    res.send(fileContent);
  } catch (error) {
    res.status(404).json({
      error: 'Failed to resolve File',
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

// Well-known endpoint
app.get('/.well-known/*', async (req: Request, res: Response) => {
  try {
    const file = req.params[0];
    const fileContent = await getFile({
      params: {
        path: '.well-known',
        file
      },
      isRemote: false
    });
    res.send(fileContent);
  } catch (error) {
    res.status(404).json({
      error: 'Failed to resolve File',
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`🔍 Resolver is running at http://localhost:${port}`);
  console.log('\n=== Using Default Verifier ===');
  console.log('All DID resolutions will use the default verifier implementation');
  console.log('==============================\n');
});
import { describe, test, expect } from "bun:test";
import { createDID } from "../src/method";
import { generateTestVerificationMethod, createTestSigner, TestCryptoImplementation } from "./utils";

describe("Paths feature", () => {
  test("creates DID without paths (default behavior)", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should only contain domain, no additional path components
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(4); // did:webvh:scid:domain
    expect(didParts[3]).toBe('example.com');
  });

  test("creates DID with single path component", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: ['api'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should contain domain + single path component
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(5); // did:webvh:scid:domain:path
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('api');
  });

  test("creates DID with multiple path components", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: ['api', 'v1', 'users'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should contain domain + multiple path components
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(7); // did:webvh:scid:domain:path1:path2:path3
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('api');
    expect(didParts[5]).toBe('v1');
    expect(didParts[6]).toBe('users');
  });

  test("creates DID with empty paths array (should behave like no paths)", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: [],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should only contain domain, no additional path components
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(4); // did:webvh:scid:domain
    expect(didParts[3]).toBe('example.com');
  });

  test("creates DID with paths containing special characters", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: ['path-with-dash', 'path_with_underscore', 'path.with.dots'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should contain domain + path components with special characters
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(7); // did:webvh:scid:domain:path1:path2:path3
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('path-with-dash');
    expect(didParts[5]).toBe('path_with_underscore');
    expect(didParts[6]).toBe('path.with.dots');
  });

  test("creates DID with domain requiring encoding and paths", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'localhost:3000',
      paths: ['api', 'health'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Should contain encoded domain + path components
    const didParts = doc.id.split(':');
    expect(didParts.length).toBe(6); // did:webvh:scid:domain:path1:path2
    expect(didParts[3]).toBe('localhost%3A3000'); // domain should be encoded
    expect(didParts[4]).toBe('api');
    expect(didParts[5]).toBe('health');
  });

  test("controller field matches DID with paths", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: ['api', 'v2'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Controller should match the DID ID
    expect(doc.controller).toBe(doc.id);
    expect(doc.controller).toContain('example.com:api:v2');
  });

  test("verification method IDs include paths", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'example.com',
      paths: ['secure', 'keys'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    
    // Verification method ID should include the paths in the DID
    expect(doc.verificationMethod[0].id).toContain('example.com:secure:keys');
    // Verify the ID starts with the correct DID prefix
    expect(doc.verificationMethod[0].id).toStartWith(doc.id + '#');
  });
}); 
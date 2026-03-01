import { describe, test, expect } from "bun:test";
import { createDID } from "../src/method";
import { generateTestVerificationMethod, createTestSigner, TestCryptoImplementation } from "./utils";

describe("Domain encoding", () => {
  test("encodes port number in DID", async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      domain: 'localhost:3000',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier
    });
    expect(doc.id).toContain('localhost%3A3000');
  });
});

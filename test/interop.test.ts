import { describe, expect, test } from "bun:test";
import { resolveDID } from "../src/method";
import { TestCryptoImplementation, generateTestVerificationMethod } from "./utils";

// Set environment variables for tests
process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID = 'true';

describe("did:webvh interoperability tests", async () => {
  const verificationMethod = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod });

  test("anywhy.ca", async () => {
    const did = "did:webvh:QmU55yaLrkhCaTsmBgEqRiUTT6zGtxSZfvJS8vWQM4tgDb:anywhy.ca:webvh-05";
    const {did: resolvedDID, meta} = await resolveDID(did, { verifier });
    expect(resolvedDID).toBe(did);
    expect(meta.nextKeyHashes.length).toBeGreaterThan(0);
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
    expect(meta.witness?.witnesses.length).toBe(3);
  })

  test("anywhy.ca large", async () => {
    const did = "did:webvh:QmahiuqDheWp6ZgRC66fsthiALqBFxvYQKk8uTQeqaBUQ2:anywhy.ca:webvh-05-large";
    const {did: resolvedDID, meta} = await resolveDID(did, { verifier });
    expect(resolvedDID).toBe(did);
    expect(meta.nextKeyHashes.length).toBeGreaterThan(0);
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
    expect(meta.witness?.witnesses.length).toBe(3);
  })

  test.skip("demo.identifier.me", async () => {
    const did = "did:tdw:QmbkyrrjFQ3Z2WiDfmesKpmeUhemaiqkWgwemovmVaTJfQ:demo.identifier.me:client:c9dd16b7-e079-43da-b0a9-36515e726c6f";
    const {did: resolvedDID, meta} = await resolveDID(did, { verifier });
    expect(resolvedDID).toBe(did);
    expect(meta.prerotation).toBe(false);
    expect(meta.portable).toBe(false);
  })

  test("gist", async () => {
    const did = "did:webvh:QmPEQVM1JPTyrvEgBcDXwjK4TeyLGSX1PxjgyeAisdWM1p:gist.githubusercontent.com:brianorwhatever:9c4633d18eb644f7a47f93a802691626:raw";
    const {did: resolvedDID, meta} = await resolveDID(did, { verifier });
    expect(resolvedDID).toBe(did);
    expect(meta.prerotation).toBe(false);
    expect(meta.portable).toBe(false);
  })
});

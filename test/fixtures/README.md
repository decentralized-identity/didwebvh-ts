# Cross-version fixtures

did:webvh logs written by didwebvh-ts 2.8.0, the last 2.x release. Each directory holds `did.jsonl` and `did-witness.json`. W = witnessed, U = unwitnessed.

- `2.8.0_v1.0_W`: a did:webvh:1.0 log, genesis then two updates, witnessed 2 of 3 with every entry approved by `witness-1` and `witness-2`. It must keep resolving.
- `2.8.0_v0.5_U`: a did:webvh:0.5 log, genesis then two updates, unwitnessed. It must be rejected, and so must its first line on its own, a genesis-only v0.5 log.

All keys are deterministic Ed25519 test keys: each secret key is SHA-256 of the UTF-8 string `didwebvh-weight-test/<name>`, for `controller`, `witness-1`, `witness-2` and `witness-3`. They are public by construction and must never be used outside tests. DIDs use the host `example.com`.

Do not edit these files: their hashes and signatures cover their contents.

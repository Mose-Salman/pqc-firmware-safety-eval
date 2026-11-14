# Synthetic firmware update threat model

## Protected assets

An independently designed toy firmware updater receives an image, a JSON manifest, and a FIPS 205 SLH-DSA signature. Trusted signing keys are pinned in local policy. The authorized verifier must validate every field listed below before approving an update.

The signed manifest includes: algorithm, target, product, channel, version, expires_at, key_id, and SHA-256 of the image. The signature covers the canonical manifest JSON. Policy includes the expected target, product, release channel, installed version, maximum image size, current time, allowed algorithm, and trusted public keys.

## Security contract

1. Verify the signature cryptographically against the public key selected by the signed key identifier.
2. Bind the image bytes to the signed manifest with SHA-256.
3. Match the manifest algorithm to the pinned SLH-DSA parameter identifier.
4. Match target and product to local policy.
5. Require a monotonically increasing integer firmware version.
6. Enforce the allowed release channel.
7. Require an integer expiration time strictly greater than policy.now.
8. Enforce the maximum image length.
9. Reject missing or unknown key identifiers.
10. Reject any failed or malformed verification.

## Controlled fault families

| Family | Deliberate defective behavior | Challenge |
|---|---|---|
| signature | Relies on nonempty signature without verifying it | Corrupt signature bytes |
| image_hash | Omits image digest comparison | Change firmware bytes without resigning |
| target | Omits device target equality | Sign a manifest for another target |
| product | Omits product equality | Sign a manifest for another product |
| rollback | Omits installed-version monotonicity | Sign a non-increasing version |
| algorithm | Omits algorithm identity check | Sign an inconsistent scheme label |
| key_binding | Uses first trusted key instead of signed key ID | Claim second key but sign with first |
| size | Omits maximum image-size enforcement | Sign oversized firmware |
| expiry | Omits signed expiration-time enforcement | Sign an expired manifest |
| channel | Omits release-channel restriction | Sign a debug-channel manifest |

All challenges are generated within a local temporary directory using newly created research keys. The defective implementation is approved by the oracle only when it accepts its designated security-policy-violating challenge. This is a bounded test of specific missing checks, not an attack on SLH-DSA's cryptographic security.

## Out of scope

No production bootloader, device exploitation, malformed native parsers, side-channel attacks, downgrade across authentic key-rotation mechanisms, supply-chain trust establishment, network transport, or privileged hardware access.

This project is **not** a formal security proof and is not intended to discover or exploit defects in any vendor's actual firmware.

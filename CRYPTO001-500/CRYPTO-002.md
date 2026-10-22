# CRYPTO-002 — JOSE legacy TODO/status matrix reconciliation

- **Area:** `sdk/crypto/jose`
- **Status:** Recheck
- **Kind:** Historical maintainer checklist
- **Source basis:** `jose-overview.md` as found during the Revision 1107 documentation review.

## Background

The JOSE historical status document preserves an old unchecked list:

- disable `RSA1_5`;
- JWK SHA-256 thumbprint;
- fully post-quantum JOSE draft work;
- COSE post-quantum key agreement draft work;
- Edwards-curve encryption.

The same document acknowledges that some items no longer align with current evidence: a thumbprint testcase and an AKP/ML-DSA testcase now exist. Separately, the current JOSE resource table still maps `RSA1_5`; metadata presence is not a security recommendation or policy.

## Current understanding

- The checklist is historical and cannot be read as a verified list of current gaps.
- “Disable RSA1_5” is a security-policy question as well as an implementation question; mapping or test presence alone does not establish the intended policy.
- A testcase does not establish interoperability or availability on every backend/provider.

## Next check

1. Compare each checklist item with current resource tables, implementation paths, and testcases.
2. Separate completed work, provider-gated work, unimplemented features, and security policy decisions.
3. Do not remove `RSA1_5` metadata or alter algorithms without an explicit design decision.

## History

- 2026-10-23: Migrated the stale checklist context out of source-tree documentation. No crypto code or tests changed.

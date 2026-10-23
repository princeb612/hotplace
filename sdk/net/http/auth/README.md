## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HTTP authentication and OAuth 2.0 helpers

## 1. Role

`sdk/net/http/auth` contains credential containers and scheme-specific authentication providers used by HTTP routing. It supplies a pluggable authentication path, not a complete identity provider, user database, token issuer, or authorization-policy engine.

## 2. Data Model

### Credentials and providers are separate

Credential classes hold the data used by a verification path; provider classes recognize the relevant Authorization scheme and coordinate challenge/verification behavior.

| Credential object | Stored representation in the current implementation |
|---|---|
| `basic_credentials` | Set of Base64-encoded `username:password` values |
| `digest_credentials` | Username-to-password map; optional username-hash map for Digest userhash |
| `bearer_credentials` | Access-token-to-client-id map |
| `oauth2_credentials` | OAuth-related credential data used by the OAuth helper path |
| `custom_credentials` | Application-defined credential extension point |

The providers include `basic_authentication_provider`, `digest_access_authentication_provider`, and `bearer_authentication_provider`; OAuth-related support is grouped under `oauth2`. The shared `http_authentication_provider` defines the provider contract: `try_auth()`, `request_auth()`, and `get_challenge()`.

The `http_authentication_resolver` dispatches a provider to scheme-specific verification. It supports application callbacks through `basic_resolver`, `digest_resolver`, `bearer_resolver`, and custom resolver registration. When a callback is not configured, the current implementation can use the built-in credential containers.

## 3. Behavior Model

### Request-to-provider flow

```text
http_router::route(session, request, response)
  │
  ├─ locate provider registered for the request URI
  │
  └─ http_authentication_resolver::resolve(...)
       │
       ▼
     provider::try_auth(...)
       │ inspect Authorization scheme
       ├─ Basic  -> resolver.basic_authenticate(...)
       ├─ Digest -> resolver.digest_authenticate(...)
       ├─ Bearer -> resolver.bearer_authenticate(...)
       └─ custom/OAuth-specific path
                │
                ▼
        application resolver callback
        or built-in credential verification
                │
        ┌───────┴────────┐
        │ success        │ failure
        ▼                ▼
 continue route     provider::request_auth(...)
 to URI handler     challenge / 401 response
```

The router owns the high-level decision to resolve the provider before invoking the URI handler. If authentication fails, it calls the provider's `request_auth()` and stops that route dispatch. On success, it proceeds to the matching URI handler or the normal fallback path. Authentication success is not the same as application authorization.

### Scheme-specific details

- **Basic:** the provider checks that the Authorization scheme is `Basic`, then passes the credential to the resolver. The default credential container stores Base64 of `username:password`; Base64 is an encoding, not encryption or password hashing. Use transport protection when credentials cross an untrusted network.
- **Digest:** the provider recognizes `Digest` and delegates challenge/request parsing and verification to the resolver. The default resolver prepares Digest parameters, obtains the configured username/password (or resolves userhash), and calls the provider's Digest calculation. The provider maintains nonce/opaque challenge state in the session and returns a challenge response when needed.
- **Bearer:** the provider recognizes `Bearer` and asks the resolver to validate the token. The built-in `bearer_credentials` implementation checks whether the token exists in its configured map; it does not itself validate a JWT signature, issuer, expiry, audience, or scope.
- **OAuth/custom:** grant/provider classes and custom resolver hooks are extension points. Their presence does not by itself imply a complete OAuth authorization server, secure token lifecycle, or a configured authorization policy.

Credential containers use locks around their in-memory maps/sets. This protects those container operations; it does not define credential rotation, persistence, rate limiting, lockout, or revocation policy for an application.

## 4. Relationships
- `basic_credentials.hpp/.cpp`, `basic_authentication_provider.hpp/.cpp`
- `digest_credentials.hpp/.cpp`, `digest_access_authentication_provider.hpp/.cpp`, `rfc2617_digest.hpp/.cpp`
- `bearer_credentials.hpp/.cpp`, `bearer_authentication_provider.hpp/.cpp`
- `oauth2_credentials.hpp/.cpp`, `oauth2.hpp/.cpp`, `custom_credentials.hpp/.cpp`
- `../http_authentication_provider.hpp/.cpp` — common provider contract.
- `../http_authentication_resolver.hpp/.cpp` — callback dispatch and built-in credential lookup.
- `../http_router.hpp/.cpp` — associates providers with URI routes and invokes the resolver.
- [HTTP core model](../http-core-model.md) and [server/client flow](../http-server-client.md) — request routing and callback boundary.
- `sdk/crypto/` — cryptographic primitives used by Digest and related code where applicable.

## 5. References
- [RFC 7617 — The 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617)
- [RFC 7616 — HTTP Digest Access Authentication](https://www.rfc-editor.org/rfc/rfc7616)
- [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)

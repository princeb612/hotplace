# MAC

`sdk/crypto/basic/mac` contains message-authentication primitives and the OTP-related implementations built on the same cryptographic layer.

## HMAC

`crypto_hmac` provides the generic HMAC operation and builder.  The OpenSSL implementation supplies the underlying MAC operation.

## CBC-HMAC

`crypto_cbc_hmac` represents the combined CBC + HMAC construction used by older protocol suites.  The existing [CBC-HMAC survey](mac/cbc-hmac-survey.md) is retained as study material because it explains the construction and the encrypt-then-MAC / MAC-then-encrypt distinction that appears in the test vectors.

## OTP

The directory also contains HMAC-based and time-based OTP support.  These are higher-level uses of HMAC but remain small enough to live beside the primitive implementation.

## Tests

HMAC and related coverage is present in `test/testcase/crypto/hash/` and signature/MAC coverage also appears under `test/testcase/crypto/sign/`.

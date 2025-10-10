/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

/**
 * RFC 9180 5.  Hybrid Public Key Encryption
 *   Table 1: HPKE Modes
 *   +===============+=======+
 *   | Mode          | Value |
 *   +===============+=======+
 *   | mode_base     | 0x00  |
 *   +---------------+-------+
 *   | mode_psk      | 0x01  |
 *   +---------------+-------+
 *   | mode_auth     | 0x02  |
 *   +---------------+-------+
 *   | mode_auth_psk | 0x03  |
 *   +---------------+-------+
 *
 * RFC 9180 7.1.  Key Encapsulation Mechanisms (KEMs)
 *   Table 2: KEM IDs
 *   +=======+===============+=========+====+===+===+====+===============+
 *   |Value  | KEM           | Nsecret |Nenc|Npk|Nsk|Auth| Reference     |
 *   +=======+===============+=========+====+===+===+====+===============+
 *   |0x0000 | Reserved      | N/A     |N/A |N/A|N/A|yes | RFC 9180      |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *   |0x0010 | DHKEM(P-256,  | 32      |65  |65 |32 |yes | [NISTCurves], |
 *   |       | HKDF-SHA256)  |         |    |   |   |    | [RFC5869]     |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *   |0x0011 | DHKEM(P-384,  | 48      |97  |97 |48 |yes | [NISTCurves], |
 *   |       | HKDF-SHA384)  |         |    |   |   |    | [RFC5869]     |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *   |0x0012 | DHKEM(P-521,  | 64      |133 |133|66 |yes | [NISTCurves], |
 *   |       | HKDF-SHA512)  |         |    |   |   |    | [RFC5869]     |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *   |0x0020 | DHKEM(X25519, | 32      |32  |32 |32 |yes | [RFC5869],    |
 *   |       | HKDF-SHA256)  |         |    |   |   |    | [RFC7748]     |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *   |0x0021 | DHKEM(X448,   | 64      |56  |56 |56 |yes | [RFC5869],    |
 *   |       | HKDF-SHA512)  |         |    |   |   |    | [RFC7748]     |
 *   +-------+---------------+---------+----+---+---+----+---------------+
 *
 * RFC 9180 7.2.  Key Derivation Functions (KDFs)
 *   Table 3: KDF IDs
 *   +========+=============+=====+===========+
 *   | Value  | KDF         | Nh  | Reference |
 *   +========+=============+=====+===========+
 *   | 0x0000 | Reserved    | N/A | RFC 9180  |
 *   +--------+-------------+-----+-----------+
 *   | 0x0001 | HKDF-SHA256 | 32  | [RFC5869] |
 *   +--------+-------------+-----+-----------+
 *   | 0x0002 | HKDF-SHA384 | 48  | [RFC5869] |
 *   +--------+-------------+-----+-----------+
 *   | 0x0003 | HKDF-SHA512 | 64  | [RFC5869] |
 *   +--------+-------------+-----+-----------+
 *
 * RFC 9180 7.2.1.  Input Length Restrictions
 *   Table 4: Application Input Limits
 *   +==================+==============+===============+===============+
 *   | Input            | HKDF-SHA256  | HKDF-SHA384   | HKDF-SHA512   |
 *   +==================+==============+===============+===============+
 *   | psk              | 2^{61} - 88  | 2^{125} - 152 | 2^{125} - 152 |
 *   +------------------+--------------+---------------+---------------+
 *   | psk_id           | 2^{61} - 93  | 2^{125} - 157 | 2^{125} - 157 |
 *   +------------------+--------------+---------------+---------------+
 *   | info             | 2^{61} - 91  | 2^{125} - 155 | 2^{125} - 155 |
 *   +------------------+--------------+---------------+---------------+
 *   | exporter_context | 2^{61} - 120 | 2^{125} - 200 | 2^{125} - 216 |
 *   +------------------+--------------+---------------+---------------+
 *   | ikm              | 2^{61} - 84  | 2^{125} - 148 | 2^{125} - 148 |
 *   | (DeriveKeyPair)  |              |               |               |
 *   +------------------+--------------+---------------+---------------+
 *
 * RFC 9180 7.3.  Authenticated Encryption with Associated Data (AEAD) Functions
 *   Table 5: AEAD IDs
 *   +========+==================+=====+=====+=====+===========+
 *   | Value  | AEAD             | Nk  | Nn  | Nt  | Reference |
 *   +========+==================+=====+=====+=====+===========+
 *   | 0x0000 | Reserved         | N/A | N/A | N/A | RFC 9180  |
 *   +--------+------------------+-----+-----+-----+-----------+
 *   | 0x0001 | AES-128-GCM      | 16  | 12  | 16  | [GCM]     |
 *   +--------+------------------+-----+-----+-----+-----------+
 *   | 0x0002 | AES-256-GCM      | 32  | 12  | 16  | [GCM]     |
 *   +--------+------------------+-----+-----+-----+-----------+
 *   | 0x0003 | ChaCha20Poly1305 | 32  | 12  | 16  | [RFC8439] |
 *   +--------+------------------+-----+-----+-----+-----------+
 *   | 0xFFFF | Export-only      | N/A | N/A | N/A | RFC 9180  |
 *   +--------+------------------+-----+-----+-----+-----------+
 *
 */

void test_dhkem_ossl_example() {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    // https://docs.openssl.org/3.5/man3/OSSL_HPKE_CTX_new/#examples
    return_t ret = errorcode_t::success;
    int rc = 0;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    OSSL_HPKE_SUITE hpke_suite = {
        OSSL_HPKE_KEM_ID_X25519,
        OSSL_HPKE_KDF_ID_HKDF_SHA256,
        OSSL_HPKE_AEAD_ID_AES_GCM_128,
    };
    OSSL_HPKE_CTX* seal_ctx = nullptr;
    OSSL_HPKE_CTX* open_ctx = nullptr;
    EVP_PKEY* priv = nullptr;
    binary_t pt;
    binary_t info;
    binary_t aad;

    pt = str2bin("a message not in a bottle");
    info = str2bin("Some info");
    aad = str2bin("\x1\x2\x3\x4\x5\x6\x7\x8");

    __try2 {
        binary_t pub;
        binary_t encap;
        binary_t ct;
        binary_t clear;

        // receiver - generate key pair
        {
            size_t publen = 512;
            pub.resize(publen);

            rc = OSSL_HPKE_keygen(hpke_suite, &pub[0], &publen, &priv, nullptr, 0, nullptr, nullptr);
            if (1 != rc) {
                ret = failed;
                __leave2;
            }
            pub.resize(publen);

            _logger->writeln([&](basic_stream& bs) -> void { dump_key(priv, &bs, 16, 3); });
            _logger->hdump("pub", pub, 16, 3);
        }
        // receiver - give this public key to the sender
        // sender - ecncapsulate and encrypt
        {
            size_t encaplen = 512;
            size_t ctlen = 512;
            encap.resize(encaplen);
            ct.resize(ctlen);

            // using the receivers public key
            seal_ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, OSSL_HPKE_ROLE_SENDER, nullptr, nullptr);
            if (nullptr == seal_ctx) {
                ret = failed;
                __leave2;
            }
            rc = OSSL_HPKE_encap(seal_ctx, &encap[0], &encaplen, &pub[0], pub.size(), &info[0], info.size());
            if (1 != rc) {
                ret = failed;
                __leave2;
            }
            encap.resize(encaplen);
            _logger->hdump("encap", encap, 16, 3);

            // encrypt data
            rc = OSSL_HPKE_seal(seal_ctx, &ct[0], &ctlen, &aad[0], aad.size(), &pt[0], pt.size());
            if (1 != rc) {
                ret = failed;
                __leave2;
            }
            ct.resize(ctlen);
            _logger->hdump("ct", ct, 16, 3);
        }
        // receiver - decapsulate and decrypt
        {
            basic_stream bs;
            size_t clearlen = 512;
            clear.resize(clearlen);

            open_ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, OSSL_HPKE_ROLE_RECEIVER, nullptr, nullptr);
            if (nullptr == open_ctx) {
                ret = failed;
                __leave2;
            }
            rc = OSSL_HPKE_decap(open_ctx, &encap[0], encap.size(), priv, &info[0], info.size());
            if (1 != rc) {
                ret = failed;
                __leave2;
            }
            rc = OSSL_HPKE_open(open_ctx, &clear[0], &clearlen, &aad[0], aad.size(), &ct[0], ct.size());
            if (1 != rc) {
                ret = failed;
                __leave2;
            }
            clear.resize(clearlen);
            _logger->hdump("clear", clear, 16, 3);
        }
    }
    __finally2 {
        OSSL_HPKE_CTX_free(open_ctx);
        OSSL_HPKE_CTX_free(seal_ctx);
        EVP_PKEY_free(priv);
    }
    _test_case.test(ret, __FUNCTION__, "HPKE");
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.2 required");
#endif
}

void test_hpke() {
    _test_case.begin("HPKE");
    return_t ret = success;

    // cf.
    // MLKEM | test/pqc |
    // DHKEM | test/key | RFC 9180

    // understanding ...
    test_dhkem_ossl_example();
}

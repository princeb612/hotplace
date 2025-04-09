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

void test_kdf_extract_expand_rfc5869() {
    _test_case.begin("RFC 5869 Appendix A.  Test Vectors");
    const OPTION& option = _cmdline->value();
    openssl_kdf kdf;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    // RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

    struct {
        const char* desc;
        const char* alg;
        int dlen;
        const char* ikm;
        const char* salt;
        const char* info;
        const char* prk;
        const char* okm;
    } expand_vector[] = {
        {
            "RFC 5869 A.1.  Test Case 1 - Basic test case with SHA-256",
            "sha256",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0x000102030405060708090a0b0c",
            "0xf0f1f2f3f4f5f6f7f8f9",
            "0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        {
            "RFC 5869 A.2.  Test Case 2 - Test with SHA-256 and longer inputs/outputs",
            "sha256",
            82,
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
            "48494a4b4c4d4e4f",
            "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
            "a8a9aaabacadaeaf",
            "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
            "f8f9fafbfcfdfeff",
            "0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87"
            "c14c01d5c1f3434f1d87",
        },
        {
            "RFC 5869 A.3.  Test Case 3 - Test with SHA-256 and zero-length salt/info",
            "sha256",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
        {
            "RFC 5869 A.4.  Test Case 4 - Basic test case with SHA-1",
            "sha1",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b",
            "0x000102030405060708090a0b0c",
            "0xf0f1f2f3f4f5f6f7f8f9",
            "0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
            "0x085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
        },
        {
            "RFC 5869 A.5.  Test Case 5 - Test with SHA-1 and longer inputs/outputs",
            "sha1",
            82,
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
            "48494a4b4c4d4e4f",
            "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
            "a8a9aaabacadaeaf",
            "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7"
            "f8f9fafbfcfdfeff",
            "0x8adae09a2a307059478d309b26c4115a224cfaf6",
            "0x0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c43"
            "00e2cff0d0900b52d3b4",
        },
        {
            "RFC 5869 A.6.  Test Case 6 - Test with SHA-1 and zero-length salt/info",
            "sha1",
            42,
            "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "0xda8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
            "0x0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        },
        {
            "RFC 5869 A.7.  Test Case 7 - Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info",
            "sha1",
            42,
            "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "",
            "",
            "0x2adccada18779e7c2077ad2eb19d3f3e731385dd",
            "0x2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        },
    };

    int i = 0;
    basic_stream bs;
    for (i = 0; i < RTL_NUMBER_OF(expand_vector); i++) {
        // 2.2 Step 1: Extract
        //  PRK = HMAC-Hash(salt, IKM)
        binary_t bin_prk;
        auto alg = expand_vector[i].alg;
        binary_t ikm = std::move(base16_decode(expand_vector[i].ikm));
        binary_t salt = std::move(base16_decode(expand_vector[i].salt));
        binary_t info = std::move(base16_decode(expand_vector[i].info));
        binary_t prk = std::move(base16_decode(expand_vector[i].prk));
        binary_t okm = std::move(base16_decode(expand_vector[i].okm));
        auto dlen = expand_vector[i].dlen;
        auto desc = expand_vector[i].desc;

        kdf.hmac_kdf_extract(bin_prk, alg, salt, ikm);
        _test_case.assert((bin_prk == prk), __FUNCTION__, "%s - KDF_Extract", desc);

        // 2.3 Step 2: Expand
        //  HKDF-Expand(PRK, info, L) -> OKM
        binary_t bin_okm;
        kdf.hkdf_expand(bin_okm, alg, dlen, bin_prk, info);
        if (option.verbose) {
            _logger->hdump("OKM", bin_okm);
        }
        _test_case.assert((bin_okm == okm), __FUNCTION__, "%s - KDF_Expand", desc);

        binary_t derived;
        kdf.hmac_kdf(derived, alg, dlen, ikm, salt, info);
        if (option.verbose) {
            _logger->hdump("HKDF", derived);
        }
        _test_case.assert((bin_okm == derived), __FUNCTION__, "%s - EVP_PKEY_derive", desc);
    }
}

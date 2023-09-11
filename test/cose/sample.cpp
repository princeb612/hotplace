/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

enum cose_header_param_t {
    // RFC 8152 Table 2: Common Header Parameters
    // RFC 9052 Table 3: Common Header Parameters
    cose_header_alg             = 1,    // int / tstr
    cose_header_crit            = 2,    // [+ label]
    cose_header_content_type    = 3,    // tstr / uint
    cose_header_kid             = 4,    // bstr
    cose_header_iv              = 5,    // bstr
    cose_header_partial_iv      = 6,    // bstr

    cose_header_counter_sig     = 7,    // COSE_Signature / [+ COSE_Signature]

    // RFC 8152 Table 27: Header Parameter for CounterSignature0
    cose_header_counter_sig0    = 9,

    // RFC 9338 Table 1: Common Header Parameters
    // RFC 9338 Table 2: New Common Header Parameters
    cose_header_counter_sig_v2  = 11,
    cose_header_counter_sig0_v2 = 12,

    // RFC 9360 Table 1: X.509 COSE Header Parameters
    cose_header_x5bag           = 32,
    cose_header_x5chain         = 33,
    cose_header_x5t             = 34,
    cose_header_x5u             = 35,
};

enum cose_key_t {
    // RFC 8152 Table 15: Direct Key
    // RFC 9053 Table 11: Direct Key
    cose_direct                 = -6,

    // RFC 8152 Table 16: Direct Key with KDF
    // RFC 9053 Table 12: Direct Key with KDF
    cose_direct_hkdf_sha_256    = -10,
    cose_direct_hkdf_sha_512    = -11,
    cose_direct_hkdf_aes_128    = -12,
    cose_direct_hkdf_aes_256    = -13,

    // RFC 8152 Table 21: Key Type Values
    // RFC 9053 Table 17: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_key_reserved   = 0,
    cose_key_okp        = 1,
    cose_key_ec2        = 2,
    cose_key_symm       = 4,

    // RFC 8230 Table 3: Key Type Values
    // RFC 9053 Table 22: Key Type Capabilities
    cose_key_rsa        = 3,

    // RFC 9053 Table 22: Key Type Capabilities
    cose_key_hss_lms    = 5,
    cose_walnutdsa      = 6,
};

enum cose_key_map_lable_t {
    // RFC 8152 Table 3: Key Map Labels
    // RFC 9052 Table 4: Key Map Labels
    cose_lable_kty      = 1,
    cose_lable_kid      = 2,
    cose_lable_alg      = 3,
    cose_lable_keyops   = 4,
    cose_lable_base_iv  = 5,
};

enum cose_keyop_t {
    // RFC 8152 Table 4: Key Operation Values
    // RFC 9052 Table 5: Key Operation Values
    cose_keyop_sign         = 1,
    cose_keyop_verify       = 2,
    cose_keyop_encrypt      = 3,
    cose_keyop_decrypt      = 4,
    cose_keyop_wrap         = 5,
    cose_keyop_unwrap       = 6,
    cose_keyop_derive_key   = 7,
    cose_keyop_derive_bits  = 8,
    cose_keyop_mac_create   = 9,
    cose_keyop_mac_verify   = 10,
};

enum cose_ec_curve_t {
    // RFC 8152 Table 22: Elliptic Curves
    // RFC 9053 Table 18: Elliptic Curves
    cose_ec_p256    = 1,
    cose_ec_p384    = 2,
    cose_ec_p521    = 3,
    cose_ec_x25519  = 4,
    cose_ec_x448    = 5,
    cose_ec_ed25519 = 6,
    cose_ec_ed448   = 7,
};

enum cose_ec_key_param_t {
    // RFC 8152 Table 23: EC Key Parameters
    // RFC 9053 Table 19: EC Key Parameters
    // cose_key_t::cose_key_ec2
    cose_ec_crv = -1,
    cose_ec_x   = -2,
    cose_ec_y   = -3,
    cose_ec_d   = -4,
};
enum cose_okp_key_param_t {
    // RFC 8152 Table 24: Octet Key Pair Parameters
    // RFC 9053 Table 20: Octet Key Pair Parameters
    // cose_key_t::cose_key_okp
    cose_okp_crv    = -1,
    cose_okp_x      = -2,
    cose_okp_d      = -4,
};
enum cose_symm_key_param_t {
    // RFC 8152 Table 25: Symmetric Key Parameters
    // RFC 9053 Table 21: Symmetric Key Parameters
    cose_symm_k = -1,
};
enum cose_rsa_key_param_t {
    // RSA 8230 Table 4: RSA Key Parameters
    cose_rsa_n      = -1,
    cose_rsa_e      = -2,
    cose_rsa_d      = -3,
    cose_rsa_p      = -4,
    cose_rsa_q      = -5,
    cose_rsa_dp     = -6,
    cose_rsa_dq     = -7,
    cose_rsa_qi     = -8,
    cose_rsa_other  = -9,
    cose_rsa_ri     = -10,
    cose_rsa_di     = -11,
    cose_rsa_ti     = -12,
};

enum cose_alg_t {

    // RFC 8152 Table 17: AES Key Wrap Algorithm Values
    // RFC 9053 Table 13: AES Key Wrap Algorithm Values
    cose_a128kw             = -3,
    cose_a192kw             = -4,
    cose_a256kw             = -5,

    // RFC 8152 Table 5: ECDSA Algorithm Values
    // RFC 9053 Table 1: ECDSA Algorithm Values
    cose_es256              = -7,
    cose_es384              = -35,
    cose_es512              = -36,

    // RFC 8152 Table 6: EdDSA Algorithm Values
    // RFC 9053 Table 2: EdDSA Algorithm Value
    cose_eddsa              = -8,

    // RFC 9054 Table 1: SHA-1 Hash Algorithm
    cose_sha1               = -14,

    // RFC 9054 Table 2: SHA-2 Hash Algorithms
    cose_sha256_64          = -15,
    cose_sha256             = -16,
    cose_sha512_256         = -17,
    cose_sha384             = -43,
    cose_sha512             = -44,

    // RFC 9054 Table 3: SHAKE Hash Functions
    cose_shake128           = -18,
    cose_shake256           = -45,

    // RFC 8152 Table 18: ECDH Algorithm Values
    // RFC 9053 Table 14: ECDH Algorithm Values
    cose_ecdh_es_hkdf_256   = -25,
    cose_ecdh_es_hkdf_512   = -26,
    cose_ecdh_ss_hkdf_256   = -27,
    cose_ecdh_ss_hkdf_512   = -28,

    // RFC 8152 Table 20: ECDH Algorithm Values with Key Wrap
    // RFC 9053 Table 16: ECDH Algorithm Values with Key Wrap
    cose_ecdh_es_a128kw     = -29,
    cose_ecdh_es_a192kw     = -30,
    cose_ecdh_es_a256kw     = -31,
    cose_ecdh_ss_a128kw     = -32,
    cose_ecdh_ss_a192kw     = -33,
    cose_ecdh_ss_a256kw     = -34,

    // RFC 8230 Table 1: RSASSA-PSS Algorithm Values
    cose_ps256              = -37,
    cose_ps384              = -38,
    cose_ps512              = -39,

    // RFC 8230 Table 2: RSAES-OAEP Algorithm Values
    cose_rsaes_oaep_sha1    = -40,
    cose_rsaes_oaep_sha256  = -41,
    cose_rsaes_oaep_sha512  = -42,

    // RFC 8812 Table 2: ECDSA Algorithm Values
    cose_es256k             = -47,

    // RFC 8812 Table 1: RSASSA-PKCS1-v1_5 Algorithm Values
    cose_rs256              = -257,
    cose_rs384              = -258,
    cose_rs512              = -259,
    cose_rs1                = -65535,

    // RFC 8152 Table 9: Algorithm Value for AES-GCM
    // RFC 9053 Table 5: Algorithm Values for AES-GCM
    cose_a128_gcm           = 1,
    cose_a192_gcm           = 2,
    cose_a256_gcm           = 3,

    // RFC 8152 Table 7: HMAC Algorithm Values
    // RFC 9053 Table 3: HMAC Algorithm Values
    cose_hmac_256_64        = 4,
    cose_hmac_256_256       = 5,
    cose_hmac_384_256       = 6,
    cose_hmac_512_512       = 7,

    // RFC 8152 Table 10: Algorithm Values for AES-CCM
    // RFC 9053 Table 6: Algorithm Values for AES-CCM
    cose_aes_ccm_16_64_128  = 10,
    cose_aes_ccm_16_64_256  = 11,
    cose_aes_ccm_64_64_128  = 12,
    cose_aes_ccm_64_64_256  = 13,
    cose_aes_ccm_16_128_128 = 30,
    cose_aes_ccm_16_128_256 = 31,
    cose_aes_ccm_64_128_128 = 32,
    cose_aes_ccm_64_128_256 = 33,

    // RFC 8152 Table 8: AES-MAC Algorithm Values
    // RFC 9053 Table 4: AES-MAC Algorithm Values
    cose_aes_mac_128_64     = 14,
    cose_aes_mac_256_64     = 15,
    cose_aes_mac_128_128    = 25,
    cose_aes_mac_256_128    = 26,

    // RFC 8152 Table 11: Algorithm Value for AES-GCM
    // RFC 9053 Table 7: Algorithm Value for ChaCha20/Poly1305
    cose_chacha20_poly1305  = 24,

    // RFC 9053 Table 23: New entry in the COSE Algorithms registry
    cose_iv_generation      = 34,
};

enum cose_alg_param_t {
    // RFC 8152 Table 19: ECDH Algorithm Parameters
    // RFC 9053 Table 15: ECDH Algorithm Parameters
    cose_ephemeral_key  = -1,
    cose_static_key     = -2,
    cose_static_key_id  = -3,

    // RFC 8152 Table 13: HKDF Algorithm Parameters
    // RFC 9053 Table 9: HKDF Algorithm Parameters
    cose_salt           = -20,

    // RFC 8152 Table 14: Context Algorithm Parameters
    // RFC 9053 Table 10: Context Algorithm Parameters
    cose_partyu_id      = -21,
    cose_partyu_nonce   = -22,
    cose_partyu_other   = -23,
    cose_partyv_id      = -24,
    cose_partyv_nonce   = -25,
    cose_partyv_other   = -26,

    // RFC 9360 Table 2: Static ECDH Algorithm Values
    cose_x5t_sender     = -27,
    cose_x5u_sender     = -28,
    cose_x5chain_sender = -29,
};

void cbor_dump (cbor_object* root, uint32 expected_size, const char* text)
{
    cbor_publisher publisher;
    binary_t bin;
    buffer_stream diagnostic;

    publisher.publish (root, &diagnostic);
    publisher.publish (root, &bin);

    std::cout << diagnostic.c_str () << std::endl;

    buffer_stream bs;
    dump_memory (bin, &bs);
    std::cout << bs.c_str () << std::endl;

    _test_case.assert (expected_size == bin.size (), __FUNCTION__, text);
}

void test_rfc8152_c1_1 ()
{
    _test_case.begin ("RFC 9052 C.1.1.  Single Signature");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << new cbor_data ((byte_t*) "", 0)          // protected, bstr
            << new cbor_map ()                          // unprotected, map
            << new cbor_data ("This is the content.")   // payload, bstr/nil(detached)
            << new cbor_array ();                       // signatures
    cbor_array* signatures = (cbor_array*) (*root)[3];

    cbor_map* sig_prot = new cbor_map ();
    *sig_prot << new cbor_pair (cose_header_param_t::cose_header_alg, new cbor_data (cose_alg_t::cose_es256));

    cbor_map* sig_unprot = new cbor_map ();
    *sig_unprot << new cbor_pair (cose_header_param_t::cose_header_kid, new cbor_data ("11"));

    binary_t bin;
    constexpr char constexpr_sig[] = "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
    bin = base16_decode (constexpr_sig);
    *signatures << sig_prot << sig_unprot << new cbor_data (&bin[0], bin.size ());

    cbor_dump (root, 103, "RFC 9052 C.1.1.  Single Signature");
}

void test_rfc8152_c1_2 ()
{
    _test_case.begin ("RFC 9052 C.1.2.  Multiple Signers");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << new cbor_data ((byte_t*) "", 0)          // protected
            << new cbor_map ()                          // unprotected
            << new cbor_data ("This is the content.")   // payload
            << new cbor_array ();                       // signatures
    cbor_array* signatures = (cbor_array*) (*root)[3];

    {
        cbor_array* signature = new cbor_array ();

        cbor_map* sig_prot = new cbor_map ();
        *sig_prot << new cbor_pair (cose_header_param_t::cose_header_alg, new cbor_data (cose_alg_t::cose_es256));

        cbor_map* sig_unprot = new cbor_map ();
        *sig_unprot << new cbor_pair (cose_header_param_t::cose_header_kid, new cbor_data ("11"));

        binary_t bin;
        constexpr char constexpr_sig[] = "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
        bin = base16_decode (constexpr_sig);
        *signature << sig_prot << sig_unprot << new cbor_data (&bin[0], bin.size ());

        *signatures << signature;
    }
    {
        cbor_array* signature = new cbor_array ();

        cbor_map* sig_prot = new cbor_map ();
        *sig_prot << new cbor_pair (cose_header_param_t::cose_header_alg, new cbor_data (cose_alg_t::cose_es512));

        cbor_map* sig_unprot = new cbor_map ();
        *sig_unprot << new cbor_pair (cose_header_param_t::cose_header_kid, new cbor_data ("bilbo.baggins@hobbiton.example"));

        binary_t bin;
        constexpr char constexpr_sig[] = "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297";
        bin = base16_decode (constexpr_sig);
        *signature << sig_prot << sig_unprot << new cbor_data (&bin[0], bin.size ());

        *signatures << signature;
    }

    cbor_dump (root, 277, "RFC 9052 C.1.2.  Multiple Signers");
}

void test_rfc8152_c1_3 ()
{
    _test_case.begin ("RFC 9052 C.1.3.  Signature with Criticality");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << new cbor_map ()                          // protected
            << new cbor_map ()                          // unprotected
            << new cbor_data ("This is the content.")   // payload
            << new cbor_array ();                       // signatures

    cbor_array* prot = (cbor_array*) (*root)[0];        // protected
    *prot << new cbor_map ();
    cbor_map* item = (cbor_map*) (*prot)[0];
    cbor_array* temp = new cbor_array ();
    *temp << new cbor_data ("reserved"); // [+ label]
    *item   << new cbor_pair ("reserved", new cbor_data (false))
            << new cbor_pair (cose_header_param_t::cose_header_crit, temp);

    cbor_array* signatures = (cbor_array*) (*root)[3];

    cbor_map* sig_prot = new cbor_map ();
    *sig_prot << new cbor_pair (cose_header_param_t::cose_header_alg, new cbor_data (cose_alg_t::cose_es256));

    cbor_map* sig_unprot = new cbor_map ();
    *sig_unprot << new cbor_pair (cose_header_param_t::cose_header_kid, new cbor_data ("11"));

    *signatures << sig_prot << sig_unprot
                << new cbor_data (base16_decode ("3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c"));

    cbor_dump (root, 125, "RFC 9052 C.1.3.  Signature with Criticality");
}

int main ()
{
    // check format

    test_rfc8152_c1_1 ();
    test_rfc8152_c1_2 ();
    test_rfc8152_c1_3 ();

    // and then refactor JOSE

    _test_case.report (5);
    return _test_case.result ();
}

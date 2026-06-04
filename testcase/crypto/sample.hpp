/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CRYPTO__
#define __HOTPLACE_TEST_CRYPTO__

#include <hotplace/testcase/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;
    bool flag_slow_kdf;
    bool flag_argon2;
    bool flag_ffdhe;

    OPTION() : CMDLINEOPTION(), dump_keys(false), flag_slow_kdf(false), flag_argon2(false), flag_ffdhe(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

// hash
void test_hash_routine(hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size);
return_t test_hash_routine(hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text);

// key
struct test_vector_rfc7919_t {
    const char* desc;
    uint32 nid;
    const char* p;
    const char* q;
    const char* g;
};
extern const test_vector_rfc7919_t test_vector_rfc7919[];
extern const size_t sizeof_test_vector_rfc7919;

void testcase_advisor();

void testcase_aead_ccm();
void testcase_cipher_encrypt();
void testcase_crypto_aead();
void testcase_crypto_encrypt();
void testcase_openssl_crypt();
void testcase_testvector_cavp_blockciphers();
void testcase_testvector_rfc3394();        // keywrap
void testcase_testvector_rfc7539();        // chacha20, chacha20-poly1305
void testcase_testvector_cbc_hmac_jose();  // JOSE
void testcase_testvector_cbc_hmac_tls();   // TLS 1.2

void testcase_openssl_hash();
void testcase_rfc4226();  // HOTP
void testcase_rfc4231();  // HMAC SHA
void testcase_rfc4493();  // CMAC
void testcase_rfc6238();  // TOTP
void testcase_transcript_hash();

void testcase_hkdf();
void testcase_rfc4615();
void testcase_rfc5869();
void testcase_rfc6070();
void testcase_rfc7914();
void testcase_rfc9106();

void testcase_crypto_key();
void testcase_curves();
void testcase_der();
void testcase_dh();
void testcase_ec();
void testcase_hpke();
void testcase_key_dsa();
void testcase_key_ffdhe();
void testcase_key_mlkem();
void testcase_key_rsa();
void testcase_keyexchange();
void testcase_keygen();

void testcase_pqc_dsa();
void testcase_pqc_encode();
void testcase_pqc_hybrid_kem();
void testcase_pqc_kem();

void testcase_oqs_dsa();
void testcase_oqs_encode();
void testcase_oqs_kem();

void testcase_random();

void testcase_crypto_sign();
void testcase_ecdsa();
void testcase_testvector_ecdsa();
void testcase_testvector_dsa();
void testcase_testvector_rsassa();
void testcase_hmac();
void testcase_mldsa();
void testcase_rsassa();
void testcase_slhdsa();
void testcase_x509();

#endif

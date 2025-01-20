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

// Authenticated Encryption with AES-CBC and HMAC-SHA
// AEAD_AES_128_CBC_HMAC_SHA_256
// AEAD_AES_192_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_384
// AEAD_AES_256_CBC_HMAC_SHA_512

#define dump(var)                             \
    {                                         \
        _logger->hdump(#var, var);            \
        _logger->writeln(base16_encode(var)); \
    }

// https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
// 2.1.  Encryption
// Appendix A.  CBC Encryption and Decryption
return_t do_test_aead_aes_cbc_hmac_sha2_testvector1(const test_vector_aead_aes_cbc_hmac_sha2_t* vector) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const OPTION& option = _cmdline->value();

    __try2 {
        if (nullptr == vector) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* enc_alg = vector->enc_alg;
        const char* mac_alg = vector->mac_alg;
        binary_t k = base16_decode(vector->k);
        binary_t iv = base16_decode(vector->iv);
        binary_t a = base16_decode(vector->a);
        binary_t p = base16_decode(vector->p);
        binary_t mac_key;
        binary_t enc_key;
        binary_t ps;
        binary_t q;
        binary_t s;
        binary_t t;
        binary_t c;
        basic_stream bs;

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        // 2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
        // 2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
        // 2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
        // 2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32

        if (k.size() < std::max(digestsize, keysize)) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mac_key.insert(mac_key.end(), &k[0], &k[0] + digestsize);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            size_t pos = k.size() - keysize;
            enc_key.insert(enc_key.end(), &k[pos], &k[pos] + keysize);
        }

        /* PS (padding string) .. for PKCS#7 padding */
        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);

        uint64 aad_len = hton64(a.size() << 3);

        /* P || PS */
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_key, iv);
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(crypt_handle, p1, q);
        crypt.close(crypt_handle);

        /* S = IV || Q */
        s.insert(s.end(), iv.begin(), iv.end());
        s.insert(s.end(), q.begin(), q.end());
        if (option.verbose) {
            dump(s);
        }

        _test_case.assert(base16_decode(vector->s) == s, __FUNCTION__, "%s S = IV || CBC-ENC(ENC_KEY, P || PS)", vector->text);

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        openssl_mac mac;
        mac.hmac(mac_alg, mac_key, content, t);
        t.resize(digestsize);

        _test_case.assert(base16_decode(vector->t) == t, __FUNCTION__, "%s T = MAC(MAC_KEY, A || S || AL)", vector->text);

        /* C = S || T */
        c.insert(c.end(), s.begin(), s.end());
        c.insert(c.end(), t.begin(), t.end());

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            dump(k);
            dump(mac_key);
            dump(enc_key);
            dump(p);
            dump(iv);
            dump(a);
            dump(ps);
            dump(iv);
            dump(q);
            dump(t);
            dump(c);
        }

        _test_case.assert(base16_decode(vector->c) == c, __FUNCTION__, "%s C = S || T", vector->text);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void do_test_aead_aes_cbc_hmac_sha2_testvector2(const test_vector_aead_aes_cbc_hmac_sha2_t* vector) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    openssl_crypt aead;

    binary_t q;
    binary_t t;
    ret = aead.aes_cbc_hmac_sha2_encrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a),
                                         base16_decode(vector->p), q, t);
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(q);
    }
    _test_case.assert(base16_decode(vector->q) == q, __FUNCTION__, "encrypt %s", vector->text);
    binary_t p;
    ret = aead.aes_cbc_hmac_sha2_decrypt(vector->enc_alg, vector->mac_alg, base16_decode(vector->k), base16_decode(vector->iv), base16_decode(vector->a), q, p,
                                         t);
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);
        dump(p);
    }
    _test_case.assert(base16_decode(vector->p) == p, __FUNCTION__, "decrypt %s", vector->text);
}

void test_aead_aes_cbc_hmac_sha2() {
    _test_case.begin("Authenticated Encryption with AES-CBC and HMAC-SHA");

    for (int i = 0; i < sizeof_test_vector_aead_aes_cbc_hmac_sha2; i++) {
        const test_vector_aead_aes_cbc_hmac_sha2_t* vector = test_vector_aead_aes_cbc_hmac_sha2 + i;
        do_test_aead_aes_cbc_hmac_sha2_testvector1(vector);
        do_test_aead_aes_cbc_hmac_sha2_testvector2(vector);
    }
}

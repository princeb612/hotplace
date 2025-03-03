/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc Authenticated Encryption with AES-CBC and HMAC-SHA
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_crypt::cbc_hmac_rfc7516_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a,
                                                 const binary_t& p, binary_t& q, binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        q.clear();
        t.clear();

        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 ivsize = sizeof_iv(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        binary_t mac_key;
        binary_t enc_key;

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

        ret = cbc_hmac_rfc7516_encrypt(enc_alg, mac_alg, enc_key, mac_key, iv, a, p, q, t);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k,
                                                 const binary_t& iv, const binary_t& a, const binary_t& p, binary_t& q, binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const char* enc_algname = advisor->nameof_cipher(enc_alg, enc_mode);
    const char* mac_algname = advisor->nameof_md(mac_alg);
    ret = cbc_hmac_rfc7516_encrypt(enc_algname, mac_algname, k, iv, a, p, q, t);
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                                 const binary_t& a, const binary_t& p, binary_t& q, binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        q.clear();
        t.clear();

        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 ivsize = sizeof_iv(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        binary_t tempiv = iv;
        tempiv.resize(ivsize);

        uint64 aad_len = hton64(a.size() << 3);

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_k, iv);
#if 0  // documents described
        /* P || PS */
        binary_t ps;
        uint32 mod = p.size() % blocksize;
        uint32 imod = blocksize - mod;
        ps.insert(ps.end(), imod, imod);
        binary_t p1;
        p1.insert(p1.end(), p.begin(), p.end());
        p1.insert(p1.end(), ps.begin(), ps.end());
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.encrypt(crypt_handle, p1, q);
#else  // using openssl pkcs #7 padding
        crypt.encrypt(crypt_handle, p, q);
#endif
        crypt.close(crypt_handle);

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        /* S = IV || Q */
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        openssl_mac mac;
        mac.hmac(mac_alg, mac_k, content, t);  // t := tag
        t.resize(digestsize);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k,
                                                 const binary_t& mac_k, const binary_t& iv, const binary_t& a, const binary_t& p, binary_t& q, binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        const char* enc_algname = advisor->nameof_cipher(enc_alg, enc_mode);
        const char* mac_algname = advisor->nameof_md(mac_alg);
        ret = cbc_hmac_rfc7516_encrypt(enc_algname, mac_algname, enc_k, mac_k, iv, a, p, q, t);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a,
                                                 const binary_t& q, binary_t& p, const binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        p.clear();

        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 ivsize = sizeof_iv(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        binary_t mac_key;
        binary_t enc_key;

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

        ret = cbc_hmac_rfc7516_decrypt(enc_alg, mac_alg, enc_key, mac_key, iv, a, q, p, t);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k,
                                                 const binary_t& iv, const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const char* enc_algname = advisor->nameof_cipher(enc_alg, enc_mode);
    const char* mac_algname = advisor->nameof_md(mac_alg);
    ret = cbc_hmac_rfc7516_decrypt(enc_algname, mac_algname, k, iv, a, q, p, t);
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                                 const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        if (nullptr == enc_alg || nullptr == mac_alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 keysize = sizeof_key(hint_blockcipher);
        if (enc_k.size() < keysize) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        uint16 ivsize = sizeof_iv(hint_blockcipher);

        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::not_found;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate
        if (mac_k.size() < digestsize) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        binary_t tempiv = iv;
        tempiv.resize(ivsize);

        /* A || S || AL */
        binary_t content;
        content.insert(content.end(), a.begin(), a.end());
        /* S = IV || Q */
        content.insert(content.end(), iv.begin(), iv.end());
        content.insert(content.end(), q.begin(), q.end());
        uint64 aad_len = hton64(a.size() << 3);
        content.insert(content.end(), (byte_t*)&aad_len, (byte_t*)&aad_len + sizeof(aad_len));

        /* T = MAC(MAC_KEY, A || S || AL) */
        binary_t tag;
        openssl_mac mac;
        mac.hmac(mac_alg, mac_k, content, tag);  // t := tag
        tag.resize(digestsize);
        if (t != tag) {
            ret = errorcode_t::error_verify;
            __leave2;
        }

        binary_t ps;

        /* Q = CBC-ENC(ENC_KEY, P || PS) */
        crypt_context_t* crypt_handle = nullptr;
        openssl_crypt crypt;
        crypt.open(&crypt_handle, enc_alg, enc_k, iv);
#if 0  // documents described
        crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
        crypt.decrypt(crypt_handle, q, p);
        /* P || PS */
        // binary_t p1;
        // p1.insert(p1.end(), p.begin(), p.end());
        // p1.insert(p1.end(), ps.begin(), ps.end());
        // remove PS
        if (p.size()) {
            p.resize (p.size() - p.back());
        }
#else  // using openssl pkcs #7 padding
        crypt.decrypt(crypt_handle, q, p);
#endif
        crypt.close(crypt_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_rfc7516_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k,
                                                 const binary_t& mac_k, const binary_t& iv, const binary_t& a, const binary_t& q, binary_t& p,
                                                 const binary_t& t) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        const char* enc_algname = advisor->nameof_cipher(enc_alg, enc_mode);
        const char* mac_algname = advisor->nameof_md(mac_alg);
        ret = cbc_hmac_rfc7516_decrypt(enc_algname, mac_algname, enc_k, mac_k, iv, a, q, p, t);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace

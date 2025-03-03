/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_hmac.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_crypt::cbc_hmac_tls_encrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const binary_t& plaintext, binary_t& ciphertext) {
    return cbc_hmac_tls_encrypt(enc_alg, mac_alg, enc_k, mac_k, iv, scv, &plaintext[0], plaintext.size(), ciphertext);
}

return_t openssl_crypt::cbc_hmac_tls_encrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const byte_t* plaintext, size_t plainsize, binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    binary_t tag;
    binary_t verifydata;
    __try2 {
        if (nullptr == plaintext) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = open(&crypt_handle, enc_alg, cbc, enc_k, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto hint_cipher = advisor->hintof_blockcipher(enc_alg);
        auto blocksize = sizeof_block(hint_cipher);

        crypto_hmac_builder builder;
        hmac = builder.set(mac_alg).set(mac_k).build();
        if (hmac) {
            (*hmac).update(scv).update(uint16(plainsize), hton16).update(plaintext, plainsize).finalize(tag);
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        // plaintext || tag || 1byte
        binary_t temp;
        binary_append(temp, plaintext, plainsize);
        binary_append(temp, tag);
        uint32 mod = temp.size() % blocksize;
        uint32 imod = blocksize - mod;
        uint8 padvalue = imod - 1;

#if 1
        binary_append(temp, padvalue);
#else
        temp.insert(temp.end(), imod, padvalue);
        set(crypt_handle, crypt_ctrl_padding, 0);
#endif
        ret = encrypt(crypt_handle, temp, ciphertext);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        if (crypt_handle) {
            close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const binary_t& ciphertext, binary_t& plaintext, size_t& ptsize) {
    return cbc_hmac_tls_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, scv, &ciphertext[0], ciphertext.size(), plaintext, ptsize);
}

return_t openssl_crypt::cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const byte_t* ciphertext, size_t size, binary_t& plaintext,
                                             size_t& ptsize) {
    return_t ret = errorcode_t::success;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    binary_t tag;
    binary_t verifydata;
    __try2 {
        ptsize = 0;

        if (nullptr == ciphertext) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = open(&crypt_handle, enc_alg, cbc, enc_k, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto hint_md = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto dlen = sizeof_digest(hint_md);

        ret = decrypt(crypt_handle, ciphertext, size, plaintext);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t plainsize = plaintext.size();
        if (dlen + 1 > plainsize) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        uint16 datalen = plainsize - dlen - 1;
        binary_append(verifydata, &plaintext[datalen], dlen);
        plaintext.resize(datalen);
        ptsize = datalen;

        crypto_hmac_builder builder;
        hmac = builder.set(mac_alg).set(mac_k).build();
        if (hmac) {
            (*hmac).update(scv).update(datalen, hton16).update(plaintext).finalize(tag);
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("> tag\n");
            dump_memory(tag, &dbs, 16, 3, 0x0, dump_notrunc);
            trace_debug_event(category_crypto, crypto_event_openssl_info, &dbs);
        }

        if (tag != verifydata) {
            ret = errorcode_t::mismatch;
            __leave2;
        }

        binary_append(plaintext, tag);
    }
    __finally2 {
        if (crypt_handle) {
            close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

return_t openssl_crypt::cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const binary_t& ciphertext, binary_t& plaintext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    tag.clear();
    binary_t plaintag;
    size_t ptsize = 0;
    ret = cbc_hmac_tls_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, scv, ciphertext, plaintag, ptsize);
    tag.insert(tag.end(), plaintag.begin(), plaintag.begin() + ptsize);
    plaintag.resize(ptsize);
    plaintext = std::move(plaintag);
    return ret;
}
return_t openssl_crypt::cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                             const binary_t& iv, const binary_t& scv, const byte_t* ciphertext, size_t size, binary_t& plaintext,
                                             binary_t& tag) {
    return_t ret = errorcode_t::success;
    tag.clear();
    binary_t plaintag;
    size_t ptsize = 0;
    ret = cbc_hmac_tls_decrypt(enc_alg, mac_alg, enc_k, mac_k, iv, scv, ciphertext, size, plaintag, ptsize);
    tag.insert(tag.end(), plaintag.begin(), plaintag.begin() + ptsize);
    plaintag.resize(ptsize);
    plaintext = std::move(plaintag);
    return ret;
}

}  // namespace crypto
}  // namespace hotplace

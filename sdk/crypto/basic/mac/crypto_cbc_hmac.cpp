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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <sdk/crypto/basic/crypto_hmac.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>

namespace hotplace {
namespace crypto {

crypto_cbc_hmac::crypto_cbc_hmac() : _enc_alg(crypt_alg_unknown), _mac_alg(hash_alg_unknown), _flag(0) { _shared.make_share(this); }

crypto_cbc_hmac& crypto_cbc_hmac::set_enc(const char* enc_alg) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint_cipher = advisor->hintof_cipher(enc_alg);
    _enc_alg = typeof_alg(hint_cipher);
    return *this;
}

crypto_cbc_hmac& crypto_cbc_hmac::set_enc(crypt_algorithm_t enc_alg) {
    _enc_alg = enc_alg;
    return *this;
}

crypto_cbc_hmac& crypto_cbc_hmac::set_mac(const char* mac_alg) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
    _mac_alg = typeof_alg(hint_digest);
    return *this;
}

crypto_cbc_hmac& crypto_cbc_hmac::set_mac(hash_algorithm_t mac_alg) {
    _mac_alg = mac_alg;
    return *this;
}

crypt_algorithm_t crypto_cbc_hmac::get_enc_alg() { return _enc_alg; }

hash_algorithm_t crypto_cbc_hmac::get_mac_alg() { return _mac_alg; }

crypto_cbc_hmac& crypto_cbc_hmac::set_flag(uint16 flag) {
    _flag = flag;
    return *this;
}

uint16 crypto_cbc_hmac::get_flag() { return _flag; }

return_t crypto_cbc_hmac::split_key(const binary_t key, binary_t& enckey, binary_t& mackey) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        enckey.clear();
        mackey.clear();

        auto enc_alg = get_enc_alg();
        auto mac_alg = get_mac_alg();

        auto hint_cipher = advisor->hintof_cipher(enc_alg, cbc);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 keysize = sizeof_key(hint_blockcipher);
        uint16 ivsize = sizeof_iv(hint_blockcipher);
        uint16 blocksize = sizeof_block(hint_blockcipher);
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        if (key.size() < std::max(digestsize, keysize)) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else {
            /* MAC_KEY = initial MAC_KEY_LEN bytes of K */
            mackey.insert(mackey.end(), &key[0], &key[0] + digestsize);
            /* ENC_KEY = final ENC_KEY_LEN bytes of K */
            size_t pos = key.size() - keysize;
            enckey.insert(enckey.end(), &key[pos], &key[pos] + keysize);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

/* concatenated tag
 * case EtM : ciphertext || tag
 * case MtE : ciphertext = ENC (plaintext || tag || pad)
 */
return_t crypto_cbc_hmac::encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext,
                                  binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    ret = encrypt(enckey, mackey, iv, aad, &plaintext[0], plaintext.size(), ciphertext);
    return ret;
}

return_t crypto_cbc_hmac::encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* plaintext,
                                  size_t plainsize, binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_crypt crypt;
    crypto_hmac_builder builder;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;
    binary_t tag;

    __try2 {
        auto flag = get_flag();
        if (jose_encrypt_then_mac == flag) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto enc_alg = get_enc_alg();
        auto mac_alg = get_mac_alg();

        const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 blocksize = sizeof_block(hint_blockcipher);

        ret = crypt.open(&crypt_handle, enc_alg, cbc, enckey, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hmac = builder.set(mac_alg).set(mackey).build();
        if (nullptr == hmac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (tls_mac_then_encrypt == flag) {
            {
                // mac
                (*hmac).update(aad).update(uint16(plainsize), hton16).update(plaintext, plainsize).finalize(tag);
            }

            {
                // encrypt

                // plaintext || tag || 1byte
                binary_t temp;
                binary_append(temp, plaintext, plainsize);
                binary_append(temp, tag);
                uint32 mod = temp.size() % blocksize;
                uint32 imod = blocksize - mod;
                uint8 padvalue = imod - 1;

#if 1
                temp.insert(temp.end(), padvalue);
#else
                temp.insert(temp.end(), imod, padvalue);
                crypt.set(crypt_handle, crypt_ctrl_padding, 0);
#endif
                ret = crypt.encrypt(crypt_handle, temp, ciphertext);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }
        } else if (tls_encrypt_then_mac == flag) {
            {
                // encrypt

                binary_t temp;

                openssl_prng prng;
                prng.random(temp, blocksize);  // random

                temp.insert(temp.end(), plaintext, plaintext + plainsize);

                uint32 mod = temp.size() % blocksize;
                uint32 imod = blocksize - mod;
                uint8 padvalue = imod - 1;
#if 1
                temp.insert(temp.end(), padvalue);
#else
                temp.insert(temp.end(), imod, padvalue);
                crypt.set(crypt_handle, crypt_ctrl_padding, 0);
#endif
                ret = crypt.encrypt(crypt_handle, temp, ciphertext);
            }
            {
                // mac
                (*hmac).update(aad).update(uint16(ciphertext.size()), hton16).update(ciphertext).finalize(tag);
                ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
            }
        } else {
            ret = errorcode_t::unknown;
        }
    }
    __finally2 {
        if (crypt_handle) {
            crypt.close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

return_t crypto_cbc_hmac::decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext,
                                  binary_t& plaintext) {
    return_t ret = errorcode_t::success;
    ret = decrypt(enckey, mackey, iv, aad, &ciphertext[0], ciphertext.size(), plaintext);
    return ret;
}

return_t crypto_cbc_hmac::decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* ciphertext,
                                  size_t ciphersize, binary_t& plaintext) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_crypt crypt;
    crypto_hmac_builder builder;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;
    binary_t tag;
    binary_t mac;
    __try2 {
        auto flag = get_flag();
        if (jose_encrypt_then_mac == flag) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto enc_alg = get_enc_alg();
        auto mac_alg = get_mac_alg();

        auto hint_md = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto dlen = sizeof_digest(hint_md);
        uint16 datalen = 0;

        ret = crypt.open(&crypt_handle, enc_alg, cbc, enckey, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hmac = builder.set(mac_alg).set(mackey).build();
        if (nullptr == hmac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (tls_mac_then_encrypt == flag) {
            {
                // encrypt
                ret = crypt.decrypt(crypt_handle, ciphertext, ciphersize, plaintext);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                size_t plainsize = plaintext.size();
                if (dlen + 1 > plainsize) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }

                datalen = plainsize - dlen - 1;  // pad1
                binary_append(mac, &plaintext[datalen], dlen);
                plaintext.resize(datalen);
            }

            {
                // mac
                (*hmac).update(aad).update(datalen, hton16).update(plaintext).finalize(tag);
                if (tag != mac) {
                    ret = errorcode_t::mismatch;
                    __leave2;
                }
            }
        } else if (tls_encrypt_then_mac == flag) {
            {
                // mac
                datalen = ciphersize - dlen;
                binary_append(mac, ciphertext + datalen, dlen);
                (*hmac).update(aad).update(uint16(datalen), hton16).update(ciphertext, datalen).finalize(tag);
                if (tag != mac) {
                    ret = errorcode_t::mismatch;
                    __leave2;
                }
            }
            {
                // encrypt
                ret = crypt.decrypt(crypt_handle, ciphertext, datalen, plaintext);

                const hint_blockcipher_t* hint_blockcipher = advisor->hintof_blockcipher(enc_alg);
                if (nullptr == hint_blockcipher) {
                    ret = errorcode_t::invalid_parameter;
                    __leave2;
                }

                uint16 blocksize = sizeof_block(hint_blockcipher);

                plaintext.erase(plaintext.begin(), plaintext.begin() + blocksize);  // block
                plaintext.erase(plaintext.end() - 1);                               // pad1
            }
        } else {
            ret = errorcode_t::unknown;
        }
    }
    __finally2 {
        if (crypt_handle) {
            crypt.close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

/* separated tag */
return_t crypto_cbc_hmac::encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext,
                                  binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    ret = encrypt(enckey, mackey, iv, aad, &plaintext[0], plaintext.size(), ciphertext, tag);
    return ret;
}

return_t crypto_cbc_hmac::encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* plaintext,
                                  size_t plainsize, binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_crypt crypt;
    crypto_hmac_builder builder;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;

    __try2 {
        auto flag = get_flag();
        if (jose_encrypt_then_mac != flag) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto enc_alg = get_enc_alg();
        auto mac_alg = get_mac_alg();

        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        ret = crypt.open(&crypt_handle, enc_alg, cbc, enckey, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hmac = builder.set(mac_alg).set(mackey).build();
        if (nullptr == hmac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (jose_encrypt_then_mac == flag) {
            /* Q = CBC-ENC(ENC_KEY, P || PS) */
#if 0  // documents described
            /* P || PS */
            binary_t ps;
            uint32 mod = plainsize % blocksize;
            uint32 imod = blocksize - mod;
            ps.insert(ps.end(), imod, imod);
            binary_t p1;
            p1.insert(p1.end(), plaintext, plaintext + plainsize);
            p1.insert(p1.end(), ps.begin(), ps.end());
            crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
            crypt.encrypt(crypt_handle, p1, ciphertext);
#else  // using openssl pkcs #7 padding
            crypt.encrypt(crypt_handle, plaintext, plainsize, ciphertext);
#endif

            /* A || S || AL */
            /* S = IV || Q */

            /* T = MAC(MAC_KEY, A || S || AL) */
            (*hmac).update(aad).update(iv).update(ciphertext).update(uint64(aad.size() << 3), hton64).finalize(tag);
            tag.resize(digestsize);
        }
    }
    __finally2 {
        if (crypt_handle) {
            crypt.close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

return_t crypto_cbc_hmac::decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext,
                                  binary_t& plaintext, const binary_t& tag) {
    return_t ret = errorcode_t::success;
    ret = decrypt(enckey, mackey, iv, aad, &ciphertext[0], ciphertext.size(), plaintext, tag);
    return ret;
}

return_t crypto_cbc_hmac::decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* ciphertext,
                                  size_t ciphersize, binary_t& plaintext, const binary_t& tag) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_crypt crypt;
    crypto_hmac_builder builder;
    crypt_context_t* crypt_handle = nullptr;
    crypto_hmac* hmac = nullptr;

    __try2 {
        auto flag = get_flag();
        if (jose_encrypt_then_mac != flag) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto enc_alg = get_enc_alg();
        auto mac_alg = get_mac_alg();

        const hint_digest_t* hint_digest = advisor->hintof_digest(mac_alg);
        if (nullptr == hint_digest) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        uint16 digestsize = sizeof_digest(hint_digest);
        digestsize >>= 1;  // truncate

        ret = crypt.open(&crypt_handle, enc_alg, cbc, enckey, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hmac = builder.set(mac_alg).set(mackey).build();
        if (nullptr == hmac) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (jose_encrypt_then_mac == flag) {
            /* A || S || AL */
            /* S = IV || Q */
            /* T = MAC(MAC_KEY, A || S || AL) */
            binary_t mac;
            (*hmac).update(aad).update(iv).update(ciphertext, ciphersize).update(uint64(aad.size() << 3), hton64).finalize(mac);
            mac.resize(digestsize);
            if (tag != mac) {
                ret = errorcode_t::error_verify;
                __leave2;
            }

            binary_t ps;

            /* Q = CBC-ENC(ENC_KEY, P || PS) */
#if 0  // documents described
            crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_padding, 0);
            crypt.decrypt(crypt_handle, ciphertext, ciphersize, plaintext);
            /* P || PS */
            // binary_t p1;
            // p1.insert(p1.end(), plaintext.begin(), plaintext.end());
            // p1.insert(p1.end(), ps.begin(), ps.end());
            // remove PS
            if (plaintext.size()) {
                plaintext.resize (plaintext.size() - plaintext.back());
            }
#else  // using openssl pkcs #7 padding
            ret = crypt.decrypt(crypt_handle, ciphertext, ciphersize, plaintext);
#endif
        }
    }
    __finally2 {
        if (crypt_handle) {
            crypt.close(crypt_handle);
        }
        if (hmac) {
            hmac->release();
        }
    }
    return ret;
}

void crypto_cbc_hmac::addref() { _shared.addref(); }

void crypto_cbc_hmac::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace

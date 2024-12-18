/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2104 HMAC: Keyed-Hashing for Message Authentication
 *  RFC 4493 The AES-CMAC Algorithm
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

enum openssl_hash_context_flag_t {
    hash_hmac = (1 << 0),
    hash_cmac = (1 << 1),
};

#define OPENSSL_HASH_CONTEXT_SIGNATURE 0x20090912
#define CRYPT_HASH_DIGESTSIZE (512 >> 3)
struct openssl_hash_context_t : public hash_context_t {
    uint32 _signature;
    crypt_poweredby_t _hash_type;
    // uint32 _algorithm;
    uint32 _flags;
    EVP_MD_CTX* _md_context;        // hash
    CMAC_CTX* _cmac_context;        // CMAC
    HMAC_CTX* _hmac_context;        // HMAC
    const EVP_CIPHER* _evp_cipher;  // CMAC
    const EVP_MD* _evp_md;          // hash, HMAC
    binary_t _key;                  // CMAC, HMAC

    openssl_hash_context_t() : _signature(0), _flags(0), _md_context(nullptr), _cmac_context(nullptr), _hmac_context(nullptr) {
        // do nothing
    }
    openssl_hash_context_t(const openssl_hash_context_t& rhs)
        : _signature(rhs._signature),
          _hash_type(rhs._hash_type),
          _flags(rhs._flags),
          _evp_cipher(rhs._evp_cipher),
          _evp_md(rhs._evp_md),
          _key(rhs._key),
          _md_context(nullptr),
          _cmac_context(nullptr),
          _hmac_context(nullptr) {
        if (rhs._md_context) {
            _md_context = EVP_MD_CTX_create();
            EVP_MD_CTX_copy(_md_context, rhs._md_context);
        }
        if (rhs._cmac_context) {
            _cmac_context = CMAC_CTX_new();
            CMAC_CTX_copy(_cmac_context, rhs._cmac_context);
        }
        if (rhs._hmac_context) {
            _hmac_context = HMAC_CTX_new();
            HMAC_CTX_copy(_hmac_context, rhs._hmac_context);
        }
    }
    void swap(openssl_hash_context_t* rhs) {
        if (rhs) {
            std::swap<EVP_MD_CTX*>(_md_context, rhs->_md_context);
            std::swap<CMAC_CTX*>(_cmac_context, rhs->_cmac_context);
            std::swap<HMAC_CTX*>(_hmac_context, rhs->_hmac_context);
        }
    }
};

openssl_hash::openssl_hash() {
    // do nothing
}

openssl_hash::~openssl_hash() {
    // do nothing
}

return_t openssl_hash::open(hash_context_t** handle, const char* algorithm, const unsigned char* key, unsigned keysize) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == algorithm) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::not_supported;

        const hint_digest_t* hint_digest = advisor->hintof_digest(algorithm);
        if (hint_digest) {
            ret = open(handle, typeof_alg(hint_digest), key, keysize);
        } else {
            const hint_cipher_t* hint_cipher = advisor->hintof_cipher(algorithm);
            if (hint_cipher) {
                ret = open(handle, typeof_alg(hint_cipher), typeof_mode(hint_cipher), key, keysize);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_hash::open(hash_context_t** handle, const char* algorithm, const binary_t& key) { return open(handle, algorithm, &key[0], key.size()); }

return_t openssl_hash::open(hash_context_t** handle, hash_algorithm_t algorithm, const unsigned char* key_data, unsigned key_size) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = nullptr;

    HMAC_CTX* hmac_context = nullptr;
    EVP_MD_CTX* md_context = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_MD* method = (const EVP_MD*)advisor->find_evp_md(algorithm);
        if (nullptr == method) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        __try_new_catch(context, new openssl_hash_context_t, ret, __leave2);

        context->_signature = OPENSSL_HASH_CONTEXT_SIGNATURE;
        // context->_algorithm = algorithm;
        context->_hash_type = crypt_poweredby_t::openssl;
        context->_evp_md = method;
        context->_flags = 0;
        context->_key.resize(key_size);
        memcpy(&context->_key[0], key_data, key_size);
        if (0 == key_size) {
            md_context = EVP_MD_CTX_create(); /* OPENSSL_malloc, EVP_MD_CTX_init */

            if (nullptr == md_context) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            context->_md_context = md_context;

            EVP_DigestInit_ex(context->_md_context, context->_evp_md, nullptr);
        } else {
            context->_flags |= openssl_hash_context_flag_t::hash_hmac;

            hmac_context = HMAC_CTX_new();
            if (nullptr == hmac_context) {
                ret = errorcode_t::out_of_memory;
                __leave2;
            }
            context->_hmac_context = hmac_context;

            HMAC_Init_ex(context->_hmac_context, &context->_key[0], context->_key.size(), context->_evp_md, nullptr);
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != hmac_context) {
                HMAC_CTX_free(hmac_context);
            }
            if (nullptr != md_context) {
                EVP_MD_CTX_destroy(md_context);
            }

            if (nullptr != context) {
                delete context;
            }

            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::open(hash_context_t** handle, hash_algorithm_t algorithm, const binary_t& key) { return open(handle, algorithm, &key[0], key.size()); }

return_t openssl_hash::open(hash_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const unsigned char* key_data, unsigned key_size) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = nullptr;

    CMAC_CTX* cmac_context = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_CIPHER* method = advisor->find_evp_cipher(algorithm, mode);
        if (nullptr == method) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        __try_new_catch(context, new openssl_hash_context_t, ret, __leave2);

        context->_signature = OPENSSL_HASH_CONTEXT_SIGNATURE;
        // context->_algorithm = algorithm;
        context->_hash_type = crypt_poweredby_t::openssl;
        context->_evp_cipher = method;
        context->_flags = 0;
        context->_key.resize(key_size);
        memcpy(&context->_key[0], key_data, key_size);

        context->_flags |= openssl_hash_context_flag_t::hash_cmac;

        cmac_context = CMAC_CTX_new();
        if (nullptr == cmac_context) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }
        context->_cmac_context = cmac_context;

        CMAC_Init(context->_cmac_context, &context->_key[0], context->_key.size(), context->_evp_cipher, nullptr);

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != cmac_context) {
                CMAC_CTX_free(cmac_context);
            }

            if (nullptr != context) {
                delete context;
            }

            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::open(hash_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key) {
    return open(handle, algorithm, mode, &key[0], key.size());
}

return_t openssl_hash::close(hash_context_t* handle) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (nullptr != context->_md_context) {
            EVP_MD_CTX_destroy(context->_md_context); /* EVP_MD_CTX_cleanup, OPENSSL_free */
        }
        if (nullptr != context->_cmac_context) {
            CMAC_CTX_free(context->_cmac_context);
        }
        if (nullptr != context->_hmac_context) {
            HMAC_CTX_free(context->_hmac_context);
        }
        context->_signature = 0;
        delete context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::init(hash_context_t* handle) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (context->_flags & openssl_hash_context_flag_t::hash_cmac) {
            CMAC_Init(context->_cmac_context, &context->_key[0], context->_key.size(), context->_evp_cipher, nullptr);
        } else if (context->_flags & openssl_hash_context_flag_t::hash_hmac) {
            HMAC_Init_ex(context->_hmac_context, &context->_key[0], context->_key.size(), context->_evp_md, nullptr);
        } else {
            EVP_DigestInit_ex(context->_md_context, context->_evp_md, nullptr);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::update(hash_context_t* handle, const byte_t* source_data, size_t source_size) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (context->_flags & openssl_hash_context_flag_t::hash_cmac) {
            CMAC_Update(context->_cmac_context, source_data, source_size);
        } else if (context->_flags & openssl_hash_context_flag_t::hash_hmac) {
            HMAC_Update(context->_hmac_context, source_data, source_size);
        } else {
            EVP_DigestUpdate(context->_md_context, source_data, source_size);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::update(hash_context_t* handle, const binary_t& input) { return update(handle, &input[0], input.size()); }

return_t openssl_hash::update(hash_context_t* handle, const byte_t* data, size_t datasize, binary_t& digest) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);
    openssl_hash_context_t* handle_dup = nullptr;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == data) {
            if (datasize) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }

        ret = update(handle, data, datasize);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        handle_dup = new openssl_hash_context_t(*context);  // duplicate CTX before finalize
        finalize(handle, digest);                           // calc MD
        context->swap(handle_dup);                          // swap CTX
    }
    __finally2 {
        if (handle_dup) {
            close(handle_dup);  // close a finalized handle
        }
    }
    return ret;
}

return_t openssl_hash::update(hash_context_t* handle, const binary_t& input, binary_t& digest) { return update(handle, &input[0], input.size(), digest); }

return_t openssl_hash::finalize(hash_context_t* handle, byte_t** hash_data, size_t* hash_size) {
    return_t ret = errorcode_t::success;
    // openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);
    byte_t* buffer_allocated = nullptr;

    __try2 {
        binary_t output;
        ret = finalize(handle, output);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t size_digest = output.size();
        __try_new_catch(buffer_allocated, (byte_t*)malloc(size_digest), ret, __leave2);

        memcpy(buffer_allocated, &output[0], size_digest);

        *hash_data = buffer_allocated;
        *hash_size = size_digest;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::finalize(hash_context_t* handle, binary_t& output) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2 {
        // output.resize (0);

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (context->_flags & openssl_hash_context_flag_t::hash_cmac) {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            const hint_blockcipher_t* hint = advisor->find_evp_cipher(context->_evp_cipher);
            size_t size_digest = sizeof_block(hint);
            output.resize(size_digest);

            CMAC_Final(context->_cmac_context, &output[0], &size_digest);
            CMAC_CTX_cleanup(context->_cmac_context);
        } else {
            unsigned int size_digest = EVP_MD_size(context->_evp_md);
            output.resize(size_digest);

            if (context->_flags & openssl_hash_context_flag_t::hash_hmac) {
                HMAC_Final(context->_hmac_context, &output[0], &size_digest);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                HMAC_CTX_reset(context->_hmac_context);
#else
                HMAC_CTX_cleanup(context->_hmac_context);
#endif
            } else {
                if (EVP_MD_FLAG_XOF & EVP_MD_meth_get_flags(context->_evp_md)) {
                    // sha3 shake
                    size_digest <<= 1;
                    output.resize(size_digest);
                    EVP_DigestFinalXOF(context->_md_context, &output[0], size_digest);
                } else {
                    EVP_DigestFinal_ex(context->_md_context, &output[0], &size_digest);
                }
            }
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::free_data(void* data) {
    return_t ret = errorcode_t::success;

    if (nullptr != data) {
        free(data);
    }
    return ret;
}

return_t openssl_hash::hash(hash_context_t* handle, const byte_t* source_data, size_t source_size, binary_t& output) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2 {
        output.resize(0);

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (context->_flags & openssl_hash_context_flag_t::hash_cmac) {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            const hint_blockcipher_t* hint = advisor->find_evp_cipher(context->_evp_cipher);
            size_t size_digest = sizeof_block(hint);
            output.resize(size_digest);

            CMAC_Init(context->_cmac_context, &context->_key[0], context->_key.size(), context->_evp_cipher, nullptr);
            CMAC_Update(context->_cmac_context, source_data, source_size);
            CMAC_Final(context->_cmac_context, &output[0], &size_digest);
            CMAC_CTX_cleanup(context->_cmac_context);
        } else {
            unsigned int size_digest = EVP_MD_size(context->_evp_md);
            output.resize(size_digest);

            if (context->_flags & openssl_hash_context_flag_t::hash_hmac) {
                HMAC_Init_ex(context->_hmac_context, &context->_key[0], context->_key.size(), context->_evp_md, nullptr);
                HMAC_Update(context->_hmac_context, source_data, source_size);
                HMAC_Final(context->_hmac_context, &output[0], &size_digest);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                HMAC_CTX_reset(context->_hmac_context);
#else
                HMAC_CTX_cleanup(context->_hmac_context);
#endif
            } else {
                EVP_DigestInit_ex(context->_md_context, context->_evp_md, nullptr);
                EVP_DigestUpdate(context->_md_context, source_data, source_size);
                if (EVP_MD_FLAG_XOF & EVP_MD_meth_get_flags(context->_evp_md)) {
                    // sha3 shake
                    size_digest <<= 1;
                    output.resize(size_digest);
                    EVP_DigestFinalXOF(context->_md_context, &output[0], size_digest);
                } else {
                    EVP_DigestFinal_ex(context->_md_context, &output[0], &size_digest);
                }
            }
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::dup(hash_context_t** duplicated, hash_context_t* handle) {
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = nullptr;
    __try2 {
        if (nullptr == duplicated || nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_hash_context_t* rhs = (openssl_hash_context_t*)handle;
        __try_new_catch(context, new openssl_hash_context_t(*rhs), ret, __leave2);

        *duplicated = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

crypt_poweredby_t openssl_hash::get_type() { return crypt_poweredby_t::openssl; }

}  // namespace crypto
}  // namespace hotplace

/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>

namespace hotplace {
namespace crypto {

enum openssl_hash_context_flag_t {
    hmac = (1 << 0),
};

#define OPENSSL_HASH_CONTEXT_SIGNATURE 0x20090912
#define CRYPT_HASH_DIGESTSIZE (512 >> 3)
typedef struct _openssl_hash_context_t : public hash_context_t {
    uint32 _signature;
    crypt_poweredby_t _hash_type;
    uint32 _algorithm;
    uint32 _flags;
    EVP_MD_CTX* _md_context;
    HMAC_CTX* _hmac_context;
    const EVP_MD* _evp_md; // constexpr
    binary_t _key;

    _openssl_hash_context_t () :
        _signature (0),
        _algorithm (0),
        _flags (0),
        _md_context (nullptr),
        _hmac_context (nullptr)
    {
        // do nothing
    }

} openssl_hash_context_t;

openssl_hash::openssl_hash ()
{
    openssl_startup ();
    // do nothing
}

openssl_hash::~openssl_hash ()
{
    openssl_cleanup ();
    // do nothing
}

return_t openssl_hash::open (hash_context_t** handle, hash_algorithm_t algorithm, const unsigned char* key_data, unsigned key_size)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = nullptr;

    HMAC_CTX* hmac_context = nullptr;
    EVP_MD_CTX* md_context = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        const EVP_MD* method = (const EVP_MD*) advisor->find_evp_md (algorithm);
        if (nullptr == method) {
            ret = errorcode_t::not_supported;
            __leave2_trace (ret);
        }

        __try_new_catch (context, new openssl_hash_context_t, ret, __leave2_trace (ret));

        context->_signature = OPENSSL_HASH_CONTEXT_SIGNATURE;
        context->_algorithm = algorithm;
        context->_hash_type = crypt_poweredby_t::openssl;
        context->_evp_md = method;
        context->_flags = 0;
        context->_key.resize (key_size);
        memcpy (&context->_key[0], key_data, key_size);
        if (0 == key_size) {
            md_context = EVP_MD_CTX_create (); /* OPENSSL_malloc, EVP_MD_CTX_init */

            if (nullptr == md_context) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            context->_md_context = md_context;

            EVP_DigestInit_ex (context->_md_context, context->_evp_md, nullptr);
        } else {
            context->_flags |= openssl_hash_context_flag_t::hmac;

            hmac_context = HMAC_CTX_new ();
            if (nullptr == hmac_context) {
                ret = errorcode_t::out_of_memory;
                __leave2_trace (ret);
            }
            context->_hmac_context = hmac_context;

            HMAC_Init_ex (context->_hmac_context, &context->_key[0], context->_key.size (), context->_evp_md, nullptr);
        }

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != hmac_context) {
                HMAC_CTX_free (hmac_context);
            }
            if (nullptr != md_context) {
                EVP_MD_CTX_destroy (md_context);
            }

            if (nullptr != context) {
                delete context;
            }

            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::close (hash_context_t* handle)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        if (nullptr != context->_md_context) {
            EVP_MD_CTX_destroy (context->_md_context); /* EVP_MD_CTX_cleanup, OPENSSL_free */
        }
        if (nullptr != context->_hmac_context) {
            HMAC_CTX_free (context->_hmac_context);
        }
        context->_signature = 0;
        delete context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::init (hash_context_t* handle)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        if (context->_flags & openssl_hash_context_flag_t::hmac) {
            HMAC_Init_ex (context->_hmac_context, &context->_key[0], context->_key.size (), context->_evp_md, nullptr);
        } else {
            EVP_DigestInit_ex (context->_md_context, context->_evp_md, nullptr);
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::update (hash_context_t* handle, byte_t* source_data, size_t source_size)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        if (context->_flags & openssl_hash_context_flag_t::hmac) {
            HMAC_Update (context->_hmac_context, source_data, source_size);
        } else {
            EVP_DigestUpdate (context->_md_context, source_data, source_size);
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::finalize (hash_context_t* handle, byte_t** hash_data, size_t* hash_size)
{
    return_t ret = errorcode_t::success;
    //openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);
    byte_t* buffer_allocated = nullptr;

    __try2
    {
        binary_t output;
        ret = finalize (handle, output);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t size_digest = output.size ();
        __try_new_catch (buffer_allocated, (byte_t * ) malloc (size_digest), ret, __leave2_trace (ret));

        memcpy (buffer_allocated, &output[0], size_digest);

        *hash_data = buffer_allocated;
        *hash_size = size_digest;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::finalize (hash_context_t* handle, binary_t& output)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2
    {
        //output.resize (0);

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        unsigned int size_digest = EVP_MD_size (context->_evp_md);
        output.resize (size_digest);

        if (context->_flags & openssl_hash_context_flag_t::hmac) {
            HMAC_Final (context->_hmac_context, &output[0], &size_digest);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            HMAC_CTX_reset (context->_hmac_context);
#else
            HMAC_CTX_cleanup (context->_hmac_context);
#endif
        } else {
            if (EVP_MD_FLAG_XOF & EVP_MD_meth_get_flags (context->_evp_md)) {
                size_digest <<= 1;
                output.resize (size_digest);
                EVP_DigestFinalXOF (context->_md_context, &output[0], size_digest);
            } else {
                EVP_DigestFinal_ex (context->_md_context, &output[0], &size_digest);
            }
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t openssl_hash::free_data (void* data)
{
    return_t ret = errorcode_t::success;

    if (nullptr != data) {
        free (data);
    }
    return ret;
}

return_t openssl_hash::hash (hash_context_t* handle, byte_t* source_data, size_t source_size, binary_t& output)
{
    return_t ret = errorcode_t::success;
    openssl_hash_context_t* context = static_cast<openssl_hash_context_t*>(handle);

    __try2
    {
        output.resize (0);

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (OPENSSL_HASH_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        unsigned int size_digest = EVP_MD_size (context->_evp_md);
        output.resize (size_digest);

        if (context->_flags & openssl_hash_context_flag_t::hmac) {
            HMAC_Init_ex (context->_hmac_context, &context->_key[0], context->_key.size (), context->_evp_md, nullptr);
            HMAC_Update (context->_hmac_context, source_data, source_size);
            HMAC_Final (context->_hmac_context, &output[0], &size_digest);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            HMAC_CTX_reset (context->_hmac_context);
#else
            HMAC_CTX_cleanup (context->_hmac_context);
#endif
        } else {
            EVP_DigestInit_ex (context->_md_context, context->_evp_md, nullptr);
            EVP_DigestUpdate (context->_md_context, source_data, source_size);
            EVP_DigestFinal_ex (context->_md_context, &output[0], &size_digest);
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

crypt_poweredby_t openssl_hash::get_type ()
{
    return crypt_poweredby_t::openssl;
}

}
}  // namespace
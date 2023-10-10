/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

class cbor_object_signing_encryption
{
public:
    cbor_object_signing_encryption ();
    ~cbor_object_signing_encryption ();

    return_t open (cose_context_t** handle);
    return_t close (cose_context_t* handle);

    /**
     * @brief encrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param cose_alg_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     */
    return_t encrypt (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief encrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param std::list<cose_alg_t> methods [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     */
    return_t encrypt (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief decrypt
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param binary_t const& input [in]
     * @param bool& result [out]
     */
    return_t decrypt (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);
    /**
     * @brief sign
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param cose_alg_t method [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief sign
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param std::list<cose_alg_t> methods [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief verify with kid
     * @param cose_context_t* handle [inout]
     * @param crypto_key* key [in]
     * @param binary_t const& input [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);

    static return_t clear_context (cose_context_t* handle);

    /**
     * @brief   composer
     */
    class composer
    {
    public:
        composer ();
        ~composer ();

        return_t build_protected (cbor_data** object);
        return_t build_protected (cbor_data** object, crypt_variantlist_t& input);
        return_t build_protected (cbor_data** object, cbor_map* input);
        return_t build_unprotected (cbor_map** object);
        return_t build_unprotected (cbor_map** object, crypt_variantlist_t& input);
        return_t build_data (cbor_data** object, const char* payload);
        return_t build_data (cbor_data** object, const byte_t* payload, size_t size);
        return_t build_data (cbor_data** object, binary_t const& payload);
        return_t build_data_b16 (cbor_data** object, const char* str);
    };
};

typedef cbor_object_signing_encryption COSE;

}
}  // namespace

#endif

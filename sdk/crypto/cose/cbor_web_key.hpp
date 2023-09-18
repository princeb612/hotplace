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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_KEY__
#define __HOTPLACE_SDK_CRYPTO_COSE_KEY__

#include <hotplace/sdk/crypto/basic/crypto_json_key.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace crypto {

class cbor_web_key : public crypto_json_key
{
public:
    cbor_web_key ();
    virtual ~cbor_web_key ();

    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in] base16 encoded
     * @param   const char* buffer [in]
     * @param   int flags [in] reserved
     * @return  error code (see error.hpp)
     */
    virtual return_t load (crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   byte_t* const& buffer [in]
     * @param   size_t size [in]
     * @param   int flags [in] reserved
     * @return  error code (see error.hpp)
     */
    return_t load (crypto_key* crypto_key, const byte_t* buffer, size_t size, int flags = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   binary_t* const& buffer [in]
     * @param   int flags [in] reserved
     * @return  error code (see error.hpp)
     */
    return_t load (crypto_key* crypto_key, binary_t const& buffer, int flags = 0);
    return_t load (crypto_key* crypto_key, cbor_object* root, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   char* buf [out] null-terminated
     * @param   size_t* buflen [inout]
     * @param   int flag [in] 0 public only, 1 also private
     * @return  error code (see error.hpp)
     */
    virtual return_t write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    virtual return_t write (crypto_key* crypto_key, binary_t& cbor, int flags = 0);

protected:
};

}
}  // namespace

#endif

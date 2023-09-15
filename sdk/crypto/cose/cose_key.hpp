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

namespace hotplace {
namespace crypto {

class cose_key : public crypto_json_key
{
public:
    cose_key ();
    virtual ~cose_key ();

    /**
     * @brief load JWK from a buffer
     * @param crypto_key * crypto_key [in]
     * @param const char* buffer [in]
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load (crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief write
     * @param crypto_key* crypto_key [in]
     * @param char* buf [out] null-terminated
     * @param size_t* buflen [inout]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief write JWK to a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write_json (crypto_key* crypto_key, const char* file, int flags = 0);

protected:

    /**
     * @brief parse
     * @param crypto_key* crypto_key [in]
     * @param void* json [in]
     */
    virtual return_t read (crypto_key* crypto_key, void* json);
};

}
}  // namespace

#endif

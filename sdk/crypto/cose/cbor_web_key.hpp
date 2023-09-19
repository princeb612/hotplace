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

#include <hotplace/sdk/crypto/basic/crypto_keyext.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace crypto {

class cbor_web_key : public crypto_keyext
{
public:
    cbor_web_key ();
    virtual ~cbor_web_key ();

    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in] base16 encoded string
     * @param   const char* buffer [in]
     * @param   int flags [inopt] reserved
     * @return  error code (see error.hpp)
     */
    virtual return_t load (crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   std::string const& buf [in]
     * @param   int flags [inopt] reserved
     * @return  error code (see error.hpp)
     */
    return_t load (crypto_key* crypto_key, std::string const& buf, int flags = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   byte_t* const& buffer [in]
     * @param   size_t size [in]
     * @param   int flags [inopt] reserved
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
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   cbor_object* root [in]
     * @param   int flags [inopt] reserved
     * @return  error code (see error.hpp)
     */
    return_t load (crypto_key* crypto_key, cbor_object* root, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   char* buf [out] base16 null-terminated
     * @param   size_t* buflen [inout]
     * @param   int flag [inopt] 0 public only, 1 also private
     * @return  error code (see error.hpp)
     */
    virtual return_t write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   std::string& buf [out] base16 null-terminated
     * @param   int flag [inopt] 0 public only, 1 also private
     * @return  error code (see error.hpp)
     */
    return_t write (crypto_key* crypto_key, std::string& buf, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   binary_t& cbor [out]
     * @param   int flag [inopt] 0 public only, 1 also private
     * @return  error code (see error.hpp)
     */
    return_t write (crypto_key* crypto_key, binary_t& cbor, int flags = 0);
    /**
     * @brief   key member function to write
     * @param   crypto_key* crypto_key [in]
     * @param   cbor_object** root [out] call release to free
     * @param   int flags [inopt]
     * @return  error code (see error.hpp)
     * @example
     *          crypto_key key;
     *          cwk.load (&key, input);
     *          cbor_obect* root = nullptr;
     *          cwk.write (&key, &root);
     *          cbor_publisher publisher;
     *          binary_t cbor;
     *          publisher.publish (root, &cbor); // same write
     *          buffer_stream diagnostic;
     *          publisher.publish (root, &diagnostic); // same diagnose
     *          root->release ();
     */
    return_t write (crypto_key* crypto_key, cbor_object** root, int flags = 0);
    /**
     * @brief   diagnostic
     * @param   crypto_key* crypto_key [in]
     * @param   stream_t* stream [out]
     * @param   int flags [inopt]
     */
    return_t diagnose (crypto_key* crypto_key, stream_t* stream, int flags = 0);

    /**
     * @brief load key from a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file (crypto_key* crypto_key, const char* file, int flags = 0);
    /**
     * @brief write to file
     * @param crypto_key * cryptokey [in]
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t write_file (crypto_key* cryptokey, const char* file, int flags = 0);

protected:
};

}
}  // namespace

#endif

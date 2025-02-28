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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBORWEBKEY__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBORWEBKEY__

#include <sdk/crypto/cose/types.hpp>

namespace hotplace {
namespace crypto {

class cbor_web_key : public crypto_keychain {
   public:
    cbor_web_key();
    virtual ~cbor_web_key();

    /**
     * @brief load from buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* buffer [in]
     * @param size_t size [in]
     * @param const keydesc& desc [inopt]
     * @param int flag [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   const std::string& buf [in]
     * @param   int flag [inopt] reserved
     * @return  error code (see error.hpp)
     */
    return_t load_b16(crypto_key* crypto_key, const std::string& buf, int flag = 0);
    return_t load_b16(crypto_key* crypto_key, const char* buffer, size_t size, int flag = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   byte_t* const buffer [in]
     * @param   size_t size [in]
     * @param   int flag [inopt] reserved
     * @return  error code (see error.hpp)
     */
    return_t load(crypto_key* crypto_key, const byte_t* buffer, size_t size, int flag = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   const binary_t& buffer [in]
     * @param   int flag [in] reserved
     * @return  error code (see error.hpp)
     */
    return_t load(crypto_key* crypto_key, const binary_t& buffer, int flag = 0);
    /**
     * @brief   load key from a buffer
     * @param   crypto_key * crypto_key [in]
     * @param   cbor_object* root [in]
     * @param   int flag [inopt] reserved
     * @return  error code (see error.hpp)
     */
    return_t load(crypto_key* crypto_key, cbor_object* root, int flag = 0);
    /**
     * @brief write into buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param stream_t* stream [in]
     * @param int flags [in] public_key | private_key
     * @return error code (see error.hpp)
     */
    virtual return_t write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flags = public_key);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   stream_t* stream [in]
     * @param   int flags [inopt] public_key | private_key
     * @return  error code (see error.hpp)
     */
    return_t write(crypto_key* cryptokey, stream_t* stream, int flags = public_key);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   std::string& buf [out] base16 null-terminated
     * @param   int flags [inopt] public_key | private_key
     * @return  error code (see error.hpp)
     */
    return_t write(crypto_key* crypto_key, std::string& buf, int flags = public_key);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   binary_t& cbor [out]
     * @param   int flags [inopt] public_key | private_key
     * @return  error code (see error.hpp)
     */
    return_t write(crypto_key* crypto_key, binary_t& cbor, int flags = public_key);
    /**
     * @brief   key member function to write
     * @param   crypto_key* crypto_key [in]
     * @param   cbor_object** root [out] call release to free
     * @param   int flags [inopt] public_key | private_key
     * @return  error code (see error.hpp)
     * @example
     *          crypto_key key;
     *          cwk.load (&key, input);
     *          cbor_obect* root = nullptr;
     *          cwk.write (&key, &root);
     *          cbor_publisher publisher;
     *          binary_t cbor;
     *          publisher.publish (root, &cbor); // same write
     *          basic_stream diagnostic;
     *          publisher.publish (root, &diagnostic); // same diagnose
     *          root->release ();
     */
    return_t write(crypto_key* crypto_key, cbor_object** root, int flags = public_key);
    /**
     * @brief   diagnostic
     * @param   crypto_key* crypto_key [in]
     * @param   stream_t* stream [out]
     * @param   int flags [inopt] public_key | private_key
     */
    return_t diagnose(crypto_key* crypto_key, stream_t* stream, int flags = public_key);

   protected:
    return_t do_load(crypto_key* crypto_key, cbor_object* object, int flag);
};

}  // namespace crypto
}  // namespace hotplace

#endif

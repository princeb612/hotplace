/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEYCHAIN__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEYCHAIN__

#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {
/**
 * key generator (RSA, EC, HMAC)
 */
class crypto_keychain {
   public:
    /**
     * @brief constructor
     */
    crypto_keychain();
    /**
     * @brief destructor
     */
    ~crypto_keychain();

    /**
     * @brief load key from a buffer
     * @param crypto_key * crypto_key [in]
     * @param const char* buffer [in]
     * @param int flag [in] 0 PEM, 1 Certificate
     * @return error code (see error.hpp)
     */
    virtual return_t load(crypto_key* cryptokey, const char* buffer, int flags = 0);
    /**
     * @brief write
     * @param crypto_key* cryptokey [in]
     * @param char* buf [out] null-terminated
     * @param size_t* buflen [inout]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write(crypto_key* cryptokey, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief load key from a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file(crypto_key* cryptokey, const char* file, int flags = 0);
    /**
     * @brief load PEM from a buffer
     * @param crypto_key * cryptokey [in]
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_pem(crypto_key* cryptokey, const char* buffer, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief load from a PEM file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_pem_file(crypto_key* cryptokey, const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief load Certificate from a buffer
     * @param crypto_key * cryptokey [in]
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_cert(crypto_key* cryptokey, const char* buffer, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief load from a Certificate file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_cert_file(crypto_key* cryptokey, const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief write to file
     * @param crypto_key * cryptokey [in]
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t write_file(crypto_key* cryptokey, const char* file, int flags = 0);
    /**
     * @brief write PEM to a file
     * @param crypto_key * cryptokey [in]
     * @param stream_t* stream [out]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    return_t write_pem(crypto_key* cryptokey, stream_t* stream, int flags = 0);

    /**
     * @brief write PEM to a file
     * @param crypto_key * cryptokey [in]
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    return_t write_pem_file(crypto_key* cryptokey, const char* file, int flags = 0);

    /**
     * @brief   RSA
     */
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, size_t bits, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                     const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc);
    return_t add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& p, const binary_t& q, const binary_t& dp,
                     const binary_t& dq, const binary_t& qi, const binary_t& d, const keydesc& desc);
    return_t add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                         const char* dq, const char* qi, const keydesc& desc);
    return_t add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                          const char* dq, const char* qi, const keydesc& desc);
    return_t add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                         const char* dq, const char* qi, const keydesc& desc);

    /**
     * @brief   EC
     */
    return_t add_ec(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, uint32 nid, jwa_t alg, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);

    return_t add_ec(crypto_key* cryptokey, const char* curve, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, const char* curve, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);

    return_t add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc);
    return_t add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, uint8 ybit, const binary_t& d, const keydesc& desc);
    return_t add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, uint8 ybit, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, uint8 ybit, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, uint8 ybit, const char* d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, uint8 ybit, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, uint8 ybit, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, uint8 ybit, const char* d, const keydesc& desc);

    /**
     * @brief   OCT
     */
    return_t add_oct(crypto_key* cryptokey, size_t size, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, const binary_t& k, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, const keydesc& desc);
    return_t add_oct(crypto_key* cryptokey, jwa_t alg, const binary_t& k, const keydesc& desc);
    return_t add_oct_b64(crypto_key* cryptokey, const char* k, const keydesc& desc);
    return_t add_oct_b64u(crypto_key* cryptokey, const char* k, const keydesc& desc);
    return_t add_oct_b16(crypto_key* cryptokey, const char* k, const keydesc& desc);

    /**
     * @brief   DH
     */
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const keydesc& desc);
    return_t add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);

    /**
     * @brief   return key
     * @param   crypto_key* key [in]
     * @param   const std::string& kid [in]
     * @param   crypto_kty_t kty [in]
     * @param   return_t& code [out]
     * @remarks
     *          return key, errorcode_t::success       : kid found
     *          return key, errorcode_t::inaccurate    : not found kid, but kty exists
     *          return nullptr, errorcode_t::not_exist : not exist kid nor kty
     */
    const EVP_PKEY* choose(crypto_key* key, const std::string& kid, crypto_kty_t kty, return_t& code);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif

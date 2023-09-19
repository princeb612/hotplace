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

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOJSONKEY__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOJSONKEY__

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/io/basic/json.hpp>

namespace hotplace {
namespace crypto {

class crypto_json_key
{
public:
    crypto_json_key ();
    virtual ~crypto_json_key ();

    /**
     * @brief load key from a buffer
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

    /**
     * @brief load PEM from a buffer
     * @param crypto_key * cryptokey [in]
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_pem (crypto_key* cryptokey, const char* buffer, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief load from a PEM file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_pem_file (crypto_key* crypto_key, const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief write PEM to a file
     * @param crypto_key * cryptokey [in]
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    return_t write_pem_file (crypto_key* cryptokey, const char* file, int flags = 0);

protected:

    /**
     * @brief add
     * @param crypto_key* crypto_key
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* n [in] public key
     * @param const char* e [in] public key
     * @param const char* d [inopt] private key
     * @param const char* p [inopt]
     * @param const char* q [inopt]
     * @param const char* dp [inopt]
     * @param const char* dq [inopt]
     * @param const char* qi [inopt]
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa_b64u (crypto_key* crypto_key, const char* kid, const char* alg, const char* n, const char* e, const char* d,
                           const char* p = nullptr,
                           const char* q = nullptr,
                           const char* dp = nullptr,
                           const char* dq = nullptr,
                           const char* qi = nullptr,
                           crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa (crypto_key* crypto_key, const char* kid, const char* alg,
                      const byte_t* n, size_t size_n, const byte_t* e, size_t size_e, const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa (crypto_key* crypto_key, const char* kid, const char* alg,
                      binary_t const& n, binary_t const& e, binary_t const& d, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief add
     * @param crypto_key* crypto_key
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* curve [in]
     * @param const char* x [in] public key
     * @param const char* y [in] public key, EC2 (not null), OKP (null)
     * @param const char* d [inopt] private key, private (not null), public (null)
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_ec_b64u (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                          const char* x, const char* y, const char* d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                     const byte_t* x, size_t size_x, const byte_t* y, size_t size_y, const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                     binary_t const& x, binary_t const& y, binary_t const& d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec (crypto_key* crypto_key, const char* kid, const char* alg, uint32 nid,
                     binary_t const& x, binary_t const& y, binary_t const& d, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief add
     * @param crypto_key* crypto_key
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* k [in]
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_oct_b64u (crypto_key* crypto_key, const char* kid, const char* alg, const char* k,
                           crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct (crypto_key* crypto_key, const char* kid, const char* alg, const byte_t* k, size_t size_k,
                      crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct (crypto_key* crypto_key, const char* kid, const char* alg, binary_t const& k,
                      crypto_use_t use = crypto_use_t::use_any);
};

}
}  // namespace

#endif

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

enum keyflag_t {
    key_ownspec = 0,   // JWK, CWK, ...
    key_pemfile = 1,   // PEM
    key_certfile = 2,  // Certificate (public key)
    key_derfile = 3,   // DER

    key_public = 0,
    key_private = 1,
};

/**
 * @brief   key chain
 * @remarks
 *                              PEM     Certificate     DER
 *          load_keyfiletype     O           O           O
 *          write_keyfiletype    O
 *
 *          add_keytype_encoding(key, nid, key parameters, keydesc)
 *              key
 *                  container class crypto_key*
 *                      search      : select, find
 *                      enumeration : for_each
 *                      key access  : get_key, get_public_key, get_private_key
 *              keytype
 *                  rsa     RSA
 *                  ec      EC2, OKP
 *                  ec2     EC2
 *                  okp     OKP
 *                  oct     oct(HMAC)
 *                  dh      DH
 *              encoding
 *                  b64     BASE64 encoding     "AAECAw=="
 *                  b64u    BASE64URL encoding  "AAECAw"
 *                  b16     BASE16 encoding     "00010203"
 *                  b16rfc  BASE16 RFC style    "00 01 02 03", "00:01:02:03", "[0, 1, 2, 3]"
 *              key parameter
 *                  RSA
 *                      nid      : nid_rsa, nid_rsapss
 *                      bits     : MUST greater than 2048
 *                      p, q     : public key
 *                      d        : private key
 *                  EC
 *                      nid      : see ec_curve_t
 *                      x, y     : public key
 *                      x, ysign : public key (compressed coordinates)
 *                      d        : private key
 *                  OKP
 *                      nid      : ec_x25519, ec_x448, ec_ed25519, ec_ed448
 *                      x        : public key
 *                      d        : private key
 *                  OCT(HMAC)
 *                      nid      : nid_oct
 *                      k        : key
 *                  DH
 *                      nid      : nid_ffdhe2048, nid_ffdhe3072, nid_ffdhe4096, nid_ffdhe6144, nid_ffdhe8192
 *                      pub      : public key
 *                      priv     : private key
 *              keydesc
 *                  kid : key identifier
 *                  algorithm : algorithm description
 *                  usage : use_any, use_enc, use_sig (each of them stand for any, encryption, signature)
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
    return_t load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_cert(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_der(crypto_key* cryptokey, const byte_t* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief write into buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param stream_t* stream [in]
     * @param int flag [in] key_public, key_private
     * @return error code (see error.hpp)
     */
    virtual return_t write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag = 0);
    return_t write_pem(crypto_key* cryptokey, stream_t* stream, int flag = 0);
    /**
     * @brief load from file
     * @param crypto_key * crypto_key [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* file [in]
     * @param const keydesc& desc [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file(crypto_key* cryptokey, keyflag_t mode, const char* file, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief write to file
     * @param crypto_key * cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t write_file(crypto_key* cryptokey, keyflag_t mode, const char* file, int flag = 0);

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
    return_t add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc);
    return_t add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
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
    return_t add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc);

    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc);

    /**
     * @brief   EC compressed
     */
    return_t add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc);

    /**
     * @brief   EC uncompressed
     */
    return_t add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec(crypto_key* cryptokey, const char* curve, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc);
    return_t add_ec_b64(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b16(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);
    return_t add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc);

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
    return_t add_oct_b16rfc(crypto_key* cryptokey, const char* k, const keydesc& desc);

    /**
     * @brief   DH
     */
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const keydesc& desc);
    return_t add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const keydesc& desc);
    return_t add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);
    return_t add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif

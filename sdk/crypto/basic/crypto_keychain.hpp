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

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/types.hpp>

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
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load(crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief write
     * @param crypto_key* crypto_key [in]
     * @param char* buf [out] null-terminated
     * @param size_t* buflen [inout]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write(crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief load key from a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file(crypto_key* crypto_key, const char* file, int flags = 0);
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
    return_t load_pem_file(crypto_key* crypto_key, const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
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
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     * @example
     *    crypto_keychain keyset;
     *    std::string kid;
     *    EVP_PKEY* pkey1 = nullptr, pkey2 = nullptr;
     *    keygen.add_rsa(&crypto_key, "kid.1", 2048);
     *    keygen.add_rsa(&crypto_key, "kid.2", 2048);
     *    pkey1 = crypto_key.find_first_of(crypto_key_t::kty_rsa, kid);
     *    pkey2 = crypto_key.get_by_name(crypto_key_t::kty_rsa, "kid.2");
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t const& n [in]
     * @param binary_t const& e [in]
     * @param binary_t const& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, binary_t const& n, binary_t const& e, binary_t const& d,
                     crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [inopt]
     * @param binary_t const& n [in]
     * @param binary_t const& e [in]
     * @param binary_t const& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t const& n, binary_t const& e, binary_t const& d,
                     crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t const& n [in]
     * @param binary_t const& e [in]
     * @param binary_t const& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, binary_t const& n, binary_t const& e, binary_t const& d, binary_t const& p,
                     binary_t const& q, binary_t const& dp, binary_t const& dq, binary_t const& qi, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param binary_t const& n [in]
     * @param binary_t const& e [in]
     * @param binary_t const& d [inopt]
     * @param binary_t const& p [inopt]
     * @param binary_t const& q [inopt]
     * @param binary_t const& dp [inopt]
     * @param binary_t const& dq [inopt]
     * @param binary_t const& qi [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t const& n, binary_t const& e, binary_t const& d, binary_t const& p,
                     binary_t const& q, binary_t const& dp, binary_t const& dq, binary_t const& qi, crypto_use_t use = crypto_use_t::use_any);
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
    return_t add_rsa_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* n, const char* e, const char* d, const char* p = nullptr,
                          const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                          crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* n, const char* e, const char* d, const char* p = nullptr,
                         const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* n, const char* e, const char* d);
    return_t add_rsa(crypto_key* crypto_key, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e, size_t size_e, const byte_t* d,
                     size_t size_d, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, int nid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @return error code (see error.hpp)
     * @example
     *      crypto_key keys;
     *      crypto_keychain keyset;
     *
     *      binary_t x_alice;
     *      binary_t y_alice;
     *      binary_t d_alice;
     *      binary_t x_bob;
     *      binary_t y_bob;
     *      binary_t d_bob;
     *      binary_t secret_alice;
     *      binary_t secret_bob;
     *
     *      keyset.add_ec (&keys, "alice", NID_secp384r1);
     *      keyset.add_ec (&keys, "bob", NID_secp384r1);
     *
     *      EVP_PKEY* alicePrivateKey = (EVP_PKEY*) keys.get_by_name (crypto_key_t::kty_ec, "alice");
     *      EVP_PKEY* bobPrivateKey = (EVP_PKEY*) keys.get_by_name (crypto_key_t::kty_ec, "bob");
     *
     *      EVP_PKEY* alicePublicKey = (EVP_PKEY*) get_peer_key (alicePrivateKey);
     *      EVP_PKEY* bobPublicKey = (EVP_PKEY*) get_peer_key (bobPrivateKey);
     *
     *      keys.get_public_key (alicePrivateKey, x_alice, y_alice);
     *      keys.get_private_key (alicePrivateKey, d_alice);
     *      keys.get_public_key (bobPrivateKey, x_bob, y_bob);
     *      keys.get_private_key (bobPrivateKey, d_bob);
     *
     *      dh_key_agreement (alicePrivateKey, bobPublicKey, secret_alice);
     *      dh_key_agreement (bobPrivateKey, alicePublicKey, secret_bob);
     *
     *      crypto_key_free (alicePublicKey);
     *      crypto_key_free (bobPublicKey);
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, int nid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, int nid, binary_t const& x, binary_t const& y, binary_t const& d, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, int nid, binary_t const& x, binary_t const& y, binary_t const& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t const& x, binary_t const& y, binary_t const& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param binary_t const& x [in]
     * @param uint8 ybit [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t const& x, uint8 ybit, binary_t const& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t const& x, binary_t const& y, binary_t const& d,
                           crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param binary_t const& x [in]
     * @param uint8 ybit [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t const& x, uint8 ybit, binary_t const& d,
                           crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate Ed25519, Ed448
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     * @remarks
     *      1 EdDSA provides high performance on a variety of platforms;
     *      2 The use of a unique random number for each signature is not required;
     *      3 It is more resilient to side-channel attacks;
     *      4 EdDSA uses small public keys (32 or 57 bytes) and signatures (64 or 114 bytes) for Ed25519 and Ed448, respectively;
     *      5 The formulas are "complete", i.e., they are valid for all points on the curve, with no exceptions.
     *        This obviates the need for EdDSA to perform expensive point validation on untrusted public values; and
     *      6 EdDSA provides collision resilience, meaning that hash-function collisions do not break this system (only holds for PureEdDSA).
     *
     *      Ed25519 is intended to provide attack resistance comparable to quality 128-bit symmetric ciphers.
     *      Public keys are 256 bits in length and signatures are twice that size.
     *
     *      Ed25519 and Ed448 use small private keys (32 or 57 bytes respectively), small public keys (32 or 57 bytes)
     *      and small signatures (64 or 114 bytes) with high security level at the same time (128-bit or 224-bit respectively).
     */
    return_t add_ec_nid_OKP(crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t const& x, binary_t const& d,
                            crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t const& x [in]
     * @param binary_t const& y [in]
     * @param binary_t const& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, jwa_t alg, int nid, binary_t const& x, binary_t const& y, binary_t const& d,
                    crypto_use_t use = crypto_use_t::use_any);
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
    return_t add_ec_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const byte_t* x, size_t size_x, const byte_t* y, size_t size_y,
                    const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, binary_t const& x, binary_t const& y, binary_t const& d,
                    crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const char* alg, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param size_t size [in] bytes
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, size_t size, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param binary_t const& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, binary_t const& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param binary_t const& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, binary_t const& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t const& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const char* alg, binary_t const& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param binary_t const& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t const& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     * @example
     *          const char* passphrase = "password";
     *          keygen.add_oct (&key, nullptr, jwa_t::jwa_pbes2_hs256_a128kw, (byte_t*) passphrase, strlen (passphrase), crypto_use_t::use_enc);
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief add
     * @param crypto_key* crypto_key
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* k [in]
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_oct_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif

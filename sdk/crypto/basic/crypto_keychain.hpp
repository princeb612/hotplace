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
     * @param int flags [in] reserved
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
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, size_t bits = 2048, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param int nid [in]
     *          6   EVP_PKEY_RSA        NID_rsaEncryption
     *          19  EVP_PKEY_RSA2       NID_rsa
     *          912 EVP_PKEY_RSA_PSS    NID_rsassaPss
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, int nid, size_t bits = 2048, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
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
     *    pkey1 = crypto_key.find_first_of(crypto_kty_t::kty_rsa, kid);
     *    pkey2 = crypto_key.get_by_name(crypto_kty_t::kty_rsa, "kid.2");
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const binary_t& n [in]
     * @param const binary_t& e [in]
     * @param const binary_t& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                     crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                     crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [inopt]
     * @param const binary_t& n [in]
     * @param const binary_t& e [in]
     * @param const binary_t& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d,
                     crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const binary_t& n [in]
     * @param const binary_t& e [in]
     * @param const binary_t& d [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                     const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                     const binary_t& p, const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi,
                     crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param const binary_t& n [in]
     * @param const binary_t& e [in]
     * @param const binary_t& d [inopt]
     * @param const binary_t& p [inopt]
     * @param const binary_t& q [inopt]
     * @param const binary_t& dp [inopt]
     * @param const binary_t& dq [inopt]
     * @param const binary_t& qi [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                     const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                     const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief add
     * @param crypto_key* cryptokey
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
    return_t add_rsa_b64u(crypto_key* cryptokey, const char* kid, const char* alg, const char* n, const char* e, const char* d, const char* p = nullptr,
                          const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                          crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b64u(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n, const char* e, const char* d,
                          const char* p = nullptr, const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                          crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b64(crypto_key* cryptokey, const char* kid, const char* alg, const char* n, const char* e, const char* d, const char* p = nullptr,
                         const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b64(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n, const char* e, const char* d, const char* p = nullptr,
                         const char* q = nullptr, const char* dp = nullptr, const char* dq = nullptr, const char* qi = nullptr,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b16(crypto_key* cryptokey, const char* kid, const char* alg, const char* n, const char* e, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa_b16(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n, const char* e, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);

    return_t add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e, size_t size_e, const byte_t* d,
                     size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e, size_t size_e,
                     const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief ec key
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
     * @brief ec key
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
     *      const EVP_PKEY* alicePrivateKey = keys.get_by_name (crypto_kty_t::kty_ec, "alice");
     *      const EVP_PKEY* bobPrivateKey = keys.get_by_name (crypto_kty_t::kty_ec, "bob");
     *
     *      const EVP_PKEY* alicePublicKey = get_peer_key (alicePrivateKey);
     *      const EVP_PKEY* bobPublicKey = get_peer_key (bobPrivateKey);
     *
     *      keys.get_public_key (alicePrivateKey, x_alice, y_alice);
     *      keys.get_private_key (alicePrivateKey, d_alice);
     *      keys.get_public_key (bobPrivateKey, x_bob, y_bob);
     *      keys.get_private_key (bobPrivateKey, d_bob);
     *
     *      dh_key_agreement (alicePrivateKey, bobPublicKey, secret_alice);
     *      dh_key_agreement (bobPrivateKey, alicePublicKey, secret_bob);
     *
     *      crypto_key_free ((EVP_PKEY*)alicePublicKey);
     *      crypto_key_free ((EVP_PKEY*)bobPublicKey);
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, int nid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
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
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, int nid, const binary_t& x, const binary_t& y, const binary_t& d, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
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
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param const binary_t& x [in]
     * @param uint8 ybit [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, uint8 ybit, const binary_t& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief   ec key
     * @param   crypto_key* cryptokey [in]
     * @param   const char* kid [inopt]
     * @param   int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param   const binary_t& x [in]
     * @param   uint8 ybit [in]
     * @param   const binary_t& d [inopt] private key
     * @return  error code (see error.hpp)
     * @sa      crypto_key::generate
     *
     *          keychain.add_ec (key, "kid", NID_X25519, crypto_use_t::use_enc); // ok
     *          keychain.add_ec (key, "kid", NID_X25519, crypto_use_t::use_enc); // ok
     *          keychain.add_ec (key, "kid", NID_ED25519, crypto_use_t::use_sig); // ok
     *          keychain.add_ec (key, "kid", NID_ED448, crypto_use_t::use_sig); // ok
     *
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, int nid, const binary_t& x, uint8 ybit, const binary_t& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                           crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param const binary_t& x [in]
     * @param uint8 ybit [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, uint8 ybit, const binary_t& d,
                           crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate Ed25519, Ed448
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in] see ec_curve_t
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
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
    return_t add_ec_nid_OKP(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& d,
                            crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param int nid [in] see ec_curve_t
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     * @param const binary_t& d [inopt] private key
     * @return error code (see error.hpp)
     */
    return_t add_ec(crypto_key* cryptokey, const char* kid, jwa_t alg, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                    crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief add
     * @param crypto_key* cryptokey
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* curve [in]
     * @param const char* x [in] public key
     * @param const char* y [in] public key, EC2 (not null), OKP (null)
     * @param const char* d [inopt] private key, private (not null), public (null)
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_ec_b64u(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec_b64u(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b64u(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                         crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec_b64(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b64(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec_b64(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b64(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec_b16(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b16(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec_b16(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec_b16(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                        crypto_use_t use = crypto_use_t::use_any);

    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const byte_t* x, size_t size_x, const byte_t* y, size_t size_y,
                    const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const byte_t* x, size_t size_x, const byte_t* y, size_t size_y,
                    const byte_t* d, size_t size_d, crypto_use_t use = crypto_use_t::use_any);
    return_t add_ec(crypto_key* cryptokey, const char* kid, const char* alg, const char* curve, const binary_t& x, const binary_t& y, const binary_t& d,
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
     * @param const binary_t& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const binary_t& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const binary_t& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const binary_t& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const binary_t& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& k, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param jwa_t alg [in]
     * @param const binary_t& k [in]
     * @return error code (see error.hpp)
     */
    return_t add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& k, crypto_use_t use = crypto_use_t::use_any);
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
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const char* k [in]
     * @param crypto_use_t use [inopt]
     * @return error code (see error.hpp)
     */
    return_t add_oct_b64u(crypto_key* cryptokey, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct_b64(crypto_key* cryptokey, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);
    return_t add_oct_b16(crypto_key* cryptokey, const char* kid, const char* alg, const char* k, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief   DH key
     * @param   crypto_key* cryptokey [in]
     * @param   int nid [in]
     *              // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
     *              1126 NID_ffdhe2048
     *              1127 NID_ffdhe3072
     *              1128 NID_ffdhe4096
     *              1129 NID_ffdhe6144
     *              1130 NID_ffdhe8192
     * @param   const char* kid [inopt]
     */
    return_t add_dh(crypto_key* cryptokey, int nid, const char* kid);
    /**
     * @brief   DH key
     * @param   crypto_key* cryptokey [in]
     * @param   int nid [in]
     *              // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
     *              1126 NID_ffdhe2048
     *              1127 NID_ffdhe3072
     *              1128 NID_ffdhe4096
     *              1129 NID_ffdhe6144
     *              1130 NID_ffdhe8192
     * @param   const char* kid [inopt]
     * @param   const binary_t& pub [in]
     * @param   const binary_t& priv [in]
     */
    return_t add_dh(crypto_key* cryptokey, int nid, const char* kid, const binary_t& pub, const binary_t& priv);
    return_t add_dh_b64u(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv);
    return_t add_dh_b64(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv);
    return_t add_dh_b16(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv);
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

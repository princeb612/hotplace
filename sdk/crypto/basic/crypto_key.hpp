/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2016.03.16   Soo Han, Kim        implemented using openssl (codename.merlin)
 * 2021.01.23   Soo Han, Kim        RFC 8037 OKP (codename.unicorn)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

class crypto_key_object {
   public:
    crypto_key_object() : _pkey(nullptr), _use(0) {
        // do nothing
    }

    crypto_key_object(const EVP_PKEY* key, crypto_use_t use, const char* kid = nullptr, const char* alg = nullptr) : _pkey(key), _use(use) {
        if (kid) {
            _kid = kid;
        }
        if (alg) {
            _alg = alg;
        }
    }
    crypto_key_object(const crypto_key_object& key) {
        _pkey = key._pkey;
        _use = key._use;
        _kid = key._kid;
        _alg = key._alg;
    }
    crypto_key_object& set(const EVP_PKEY* key, crypto_use_t use, const char* kid = nullptr, const char* alg = nullptr) {
        _pkey = key;
        _use = _use;
        if (kid) {
            _kid = kid;
        }
        if (alg) {
            _alg = alg;
        }
        return *this;
    }
    crypto_key_object& operator=(crypto_key_object& key) {
        _pkey = key._pkey;
        _use = key._use;
        _kid = key._kid;
        _alg = key._alg;
        return *this;
    }

    const EVP_PKEY* get_pkey() { return _pkey; }
    const char* get_kid() { return _kid.c_str(); }
    std::string get_kid_string() { return _kid; }
    uint32 get_use() { return _use; }
    const char* get_alg() { return _alg.c_str(); }
    std::string get_alg_string() { return _alg; }

   private:
    const EVP_PKEY* _pkey;
    std::string _kid;
    uint32 _use;  // crypto_use_t
    std::string _alg;
};

/**
 * @brief RSA, EC, oct key container
 * @remarks
 *          crypto_key key;
 *          // generate a key
 *          key.generate (crypto_kty_t::kty_rsa, 1024, "key1");
 *          key.generate (crypto_kty_t::kty_oct, 32, "key1");
 *          // generate a key
 *          crypto_keychain keyset;
 *          keyset.add_rsa (&key, 1024);// 1024 bits
 *          keyset.add_ec (&key, ec_curve_t::ec_p256);  // NID_X9_62_prime256v1(415)
 *          keyset.add_ec (&key, ec_curve_t::ec_p384);  // NID_secp384r1(715)
 *          keyset.add_ec (&key, ec_curve_t::ec_p521);  // NID_secp521r1(716)
 *          keyset.add_ec (&key, ec_curve_t::ec_x25519);    // X25519(1034)
 *          keyset.add_ec (&key, ec_curve_t::ec_ed25519);   // Ed25519(1087)
 *          keyset.add_oct (&key, 32);                      // 32 bytes
 *          // load from JWK, PEM
 *          json_web_key jwk;
 *          jwk.load_file (&key, "rfc7515.jwk", 0);
 *          jwk.load_pem_file (&key, "test.pem");
 */
class crypto_key {
   public:
    crypto_key();
    crypto_key(const crypto_key& object);
    crypto_key(crypto_key&& object);
    ~crypto_key();

    /**
     * @brief load PEM from the buffer
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_pem(const char* buffer, int flags, crypto_use_t use);
    /**
     * @brief load from a PEM file
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_pem_file(const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief write PEM to the file
     * @param stream_t* stream [out]
     * @param int flag [in]
     * @return error code (see error.hpp)
     */
    return_t write_pem(stream_t* stream, int flags = 0);
    /**
     * @brief write PEM to the file
     * @param const char* file [in]
     * @param int flag [in]
     * @return error code (see error.hpp)
     */
    return_t write_pem_file(const char* file, int flags = 0);

    /**
     * @brief add
     * @param crypto_key_object key [in]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(crypto_key_object key, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(EVP_PKEY* key, const char* kid = nullptr, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add(EVP_PKEY* key, const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief generate
     * @param crypto_kty_t type [in] CRYPTO_KEY_TYPE
     * @param unsigned int param [in] crypto_kty_t::kty_oct in bytes
     *                                crypto_kty_t::kty_rsa in bits
     *                                crypto_kty_t::kty_ec 256, 384, 521
     *                                crypto_kty_t::kty_okp 25518, 448
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     * @remarks
     *          key.generate (crypto_kty_t::kty_oct,  32,    "kid", crypto_use_t::use_any); // oct
     *          key.generate (crypto_kty_t::kty_rsa,  2048,  "kid", crypto_use_t::use_any); // RSA
     *          key.generate (crypto_kty_t::kty_ec,   ec_keyparam_t::ec_keyparam_p256,     "kid", crypto_use_t::use_any); // EC, P-256
     *          key.generate (crypto_kty_t::kty_ec,   ec_keyparam_t::ec_keyparam_p384,     "kid", crypto_use_t::use_any); // EC, P-384
     *          key.generate (crypto_kty_t::kty_ec,   ec_keyparam_t::ec_keyparam_p521,     "kid", crypto_use_t::use_any); // EC, P-521
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp25519, "kid", crypto_use_t::use_any); // OKP, X25519 and Ed25519
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp448,   "kid", crypto_use_t::use_any); // OKP, X448 and Ed448
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp25519, "kid", crypto_use_t::use_enc); // OKP, X25519
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp448,   "kid", crypto_use_t::use_enc); // OKP, X448
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp25519, "kid", crypto_use_t::use_sig); // OKP, Ed25519
     *          key.generate (crypto_kty_t::kty_okp,  ec_keyparam_t::ec_keyparam_okp448,   "kid", crypto_use_t::use_sig); // OKP, Ed448
     */
    return_t generate(crypto_kty_t type, unsigned int param, const char* kid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate
     * @param crypto_kty_t type [in]
     * @param unsigned int param [in]
     *          cose_kty_symm, cose_kty_rsa
     *              size of key
     *          cose_kty_ec2
     *              415 : NID_X9_62_prime256v1 (prime256v1)
     *              714 : NID_secp256k1 (secp256k1), see RFC 8812 4.2.  COSE Elliptic Curves Registrations "secp256k1"
     *              715 : NID_secp384r1 (secp384r1)
     *              716 : NID_secp521r1 (secp521r1)
     *          cose_kty_okp -
     *              1034: NID_X25519
     *              1035: NID_X448
     *              1087: NID_ED25519
     *              1088: NID_ED448
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @return error code (see error.hpp)
     * @remarks
     *          key.generate_nid (crypto_kty_t::kty_oct,  32,    "kid", crypto_use_t::use_any); // oct
     *          key.generate_nid (crypto_kty_t::kty_rsa,  2048,  "kid", crypto_use_t::use_any); // RSA
     *          key.generate_nid (crypto_kty_t::kty_ec,   ec_curve_t::ec_p256, "kid", crypto_use_t::use_any); // EC, P-256
     *          key.generate_nid (crypto_kty_t::kty_ec,   ec_curve_t::ec_p256k,    "kid", crypto_use_t::use_any); // EC, secp256k1
     *          key.generate_nid (crypto_kty_t::kty_ec,   ec_curve_t::ec_p384, "kid", crypto_use_t::use_any); // EC, P-384
     *          key.generate_nid (crypto_kty_t::kty_ec,   ec_curve_t::ec_p521, "kid", crypto_use_t::use_any); // EC, P-521
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_x25519,   "kid", crypto_use_t::use_any); // OKP, X25519 only
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_x448,     "kid", crypto_use_t::use_any); // OKP, X448 only
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_ed25519,  "kid", crypto_use_t::use_any); // OKP, Ed25519 only
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_ed448,    "kid", crypto_use_t::use_any); // OKP, Ed448 only
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_x25519,   "kid", crypto_use_t::use_enc); // OKP, X25519
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_x448,     "kid", crypto_use_t::use_enc); // OKP, X448
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_ed25519,  "kid", crypto_use_t::use_sig); // OKP, Ed25519
     *          key.generate_nid (crypto_kty_t::kty_okp,  ec_curve_t::ec_ed448,    "kid", crypto_use_t::use_sig); // OKP, Ed448
     */
    return_t generate_nid(crypto_kty_t type, unsigned int param, const char* kid, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief generate
     * @param cose_kty_t kty [in] cose_kty_okp, cose_kty_ec2, cose_kty_symm, cose_kty_rsa, ...
     * @param unsigned int param [in]
     *          cose_kty_symm, cose_kty_rsa - size of key
     *          cose_kty_ec2 - cose_ec_p256, cose_ec_p384, cose_ec_p521
     *          cose_kty_okp - cose_ec_x25519, cose_ec_x448, cose_ec_ed25519, cose_ec_ed448
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @return error code (see error.hpp)
     * @remarks
     *          key.generate_cose (cose_kty_t::cose_kty_symm, 32,    "kid", crypto_use_t::use_any); // oct
     *          key.generate_cose (cose_kty_t::cose_kty_rsa,  2048,  "kid", crypto_use_t::use_any); // RSA
     *          key.generate_cose (cose_kty_t::cose_kty_ec2,  cose_ec_curve_t::cose_ec_p256,      "kid", crypto_use_t::use_any); // EC, P-256
     *          key.generate_cose (cose_kty_t::cose_kty_ec2,  cose_ec_curve_t::cose_ec_p384,      "kid", crypto_use_t::use_any); // EC, P-384
     *          key.generate_cose (cose_kty_t::cose_kty_ec2,  cose_ec_curve_t::cose_ec_p521,      "kid", crypto_use_t::use_any); // EC, P-521
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_x25519,    "kid", crypto_use_t::use_any); // OKP, X25519 only
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_x448,      "kid", crypto_use_t::use_any); // OKP, X448 only
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_ed25519,   "kid", crypto_use_t::use_any); // OKP, Ed25519 only
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_ed448,     "kid", crypto_use_t::use_any); // OKP, Ed448 only
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_x25519,    "kid", crypto_use_t::use_enc); // OKP, X25519
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_x448,      "kid", crypto_use_t::use_enc); // OKP, X448
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_ed25519,   "kid", crypto_use_t::use_sig); // OKP, Ed25519
     *          key.generate_cose (cose_kty_t::cose_kty_okp,  cose_ec_curve_t::cose_ec_ed448,     "kid", crypto_use_t::use_sig); // OKP, Ed448
     *          key.generate_cose (cose_kty_t::cose_kty_ec2,  cose_ec_curve_t::cose_ec_secp256k1, "kid", crypto_use_t::use_any); // EC, "secp256k1"
     */
    return_t generate_cose(cose_kty_t kty, unsigned int param, const char* kid, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief return any key
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* any(bool up_ref = false);
    /**
     * @brief find
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(crypt_sig_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(jws_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param cose_alg_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* select(std::string& kid, cose_alg_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypto_kty_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypto_kty_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    const EVP_PKEY* find(const char* kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);

    /**
     * @brief public key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     */
    static return_t get_public_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2);
    /**
     * @brief private key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& priv [out]
     */
    static return_t get_private_key(const EVP_PKEY* pkey, binary_t& priv);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @param crypto_kty_t type [out] crypto_kty_t::kty_oct, crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_key(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve = false);
    /**
     * @brief key
     * @param const EVP_PKEY* pkey [in]
     * @param crypto_kty_t type [out] crypto_kty_t::kty_oct, crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec
     * @parambinary_t& priv [out]
     * @param bool preserve [inopt] preserve leading zero (default false)
     */
    static return_t get_privkey(const EVP_PKEY* pkey, crypto_kty_t& type, binary_t& priv, bool preserve = false);
    /**
     * @brief clear
     * @remarks decrement a reference counter of keys and clear a container
     */
    void clear();
    /**
     * size
     */
    size_t size();

    return_t append(crypto_key* source);

    int addref();
    int release();

    /**
     * @brief dump
     * @example
     *  void dump_crypto_key (crypto_key_object* key, void*)
     *  {
     *      uint32 nid = 0;
     *      nidof_evp_pkey (key->get_pkey(), nid);
     *      printf ("nid %i kid %s alg %s use %i\n", nid, key->get_kid(), key->get_alg(), key->get_use());
     *  }
     *  void load_key_and_dump ()
     *  {
     *      crypto_key key;
     *      json_web_key jwk;
     *      jwk.load_file (&key, "rfc7515.jwk", 0);
     *      key.for_each (dump_crypto_key, nullptr);
     *  }
     */
    void for_each(void (*)(crypto_key_object*, void*), void* param);

   protected:
    /**
     * @brief extract
     * @param const EVP_PKEY* pkey [in]
     * @param CRYPTO_KEY_FLAG flag [in] CRYPTO_KEY_PUBLIC, CRYPTO_KEY_PRIVATE
     * @param crypto_kty_t type [out]
     * @param crypt_datamap_t& datamap [out]
     * @param bool plzero [inopt] preserve leading zero (default false)
     */
    static return_t extract(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero = false);

   private:
    /**
     * numberof (kid) = combination (type, enc)
     * @example
     *  "kty"="RSA" "use"="enc" "kid"="key1"    // ok
     *  "kty"="RSA" "use"="sig" "kid"="key1"    // ok
     *  "kty"="EC"  "use"="enc" "kid"="key1"    // ok
     *  "kty"="EC"  "use"="sig" "kid"="key1"    // ok
     *  "kty"="oct" "use"="enc" "kid"="key1"    // ok
     *  "kty"="oct" "use"="sig" "kid"="key1"    // ok
     *  "kty"="OKP" "use"="enc" "kid"="key1"    // ok
     *  "kty"="OKP" "use"="sig" "kid"="key1"    // ok
     */
    typedef std::multimap<std::string, crypto_key_object> crypto_key_map_t;
    crypto_key_map_t _key_map;

    critical_section _lock;
    t_shared_reference<crypto_key> _shared;
};

/**
 * @param crypto_key_object key [in]
 */
crypto_kty_t typeof_crypto_key(crypto_key_object& key);

/**
 * @brief   dump
 * @param   const EVP_PKEY* pkey [in]
 * @param   stream_t* stream [out]
 * @param   uint8 hex_part [inopt] default 15
 * @param   uint8 indent [inopt] default 4
 * @param   uint8 flag [inopt]
 * @sample
 *          // case.1
 *          bs.printf("informations");
 *          dump_key(pkey, &bs);  // bs.clear()
 *
 *          // case.2
 *          bs.printf("informations");
 *          dump_key(pkey, &bs, 15, 4, dump_notrunc);
 */
return_t dump_key(const EVP_PKEY* pkey, stream_t* stream, uint8 hex_part = 15, uint8 indent = 4, uint8 flag = 0);
/**
 * @brief   pem
 * @param   const EVP_PKEY* pkey [in]
 * @param   stream_t* stream [out]
 */
return_t write_pem(const EVP_PKEY* pkey, stream_t* stream);
/**
 * @brief   pem
 * @param   const EVP_PKEY* pkey [in]
 * @param   BIO* bio [out]
 */
return_t write_pem(const EVP_PKEY* pkey, BIO* bio);

}  // namespace crypto
}  // namespace hotplace

#endif

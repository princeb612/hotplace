/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOKEY__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

typedef struct _crypto_key_object_t {
    EVP_PKEY* pkey;
    std::string kid;
    uint32 use;     // crypto_use_t
    uint32 keybits; // todo
    std::string alg;

    _crypto_key_object_t () : pkey (nullptr), use (0), keybits (0)
    {
        // do nothing
    }
    _crypto_key_object_t (EVP_PKEY* _key, crypto_use_t _use, const char* _kid, const char* _alg)
        : pkey (_key), use (_use), keybits (0)
    {
        if (_kid) {
            kid = _kid;
        }
        if (_alg) {
            alg = _alg;
        }
    }
    _crypto_key_object_t& set (EVP_PKEY* _key, crypto_use_t _use, const char* _kid, const char* _alg)
    {
        pkey = _key;
        use = _use;
        if (_kid) {
            kid = _kid;
        }
        if (_alg) {
            alg = _alg;
        }
        return *this;
    }
    _crypto_key_object_t& set_keybits (uint32 size)
    {
        keybits = size;
        return *this;
    }
    const char* get_kid ()
    {
        return kid.c_str ();
    }
    uint32 get_use ()
    {
        return use;
    }
    uint32 get_keybits ()
    {
        return keybits;
    }
    const char* get_alg ()
    {
        return alg.c_str ();
    }
} crypto_key_object_t;

/*
 * @brief RSA, EC, oct key container
 * @remarks
 *          crypto_key key;
 *          // generate a key
 *          key.generate (CRYPTO_KEY_RSA, 1024, "key1");
 *          key.generate (CRYPTO_KEY_HMAC, 32, "key1");
 *          // generate a key
 *          crypto_keychain keyset;
 *          keyset.add_rsa (&key, 1024);// 1024 bits
 *          keyset.add_ec (&key, 415);  // NID_X9_62_prime256v1
 *          keyset.add_ec (&key, 715);  // NID_secp384r1
 *          keyset.add_ec (&key, 716);  // NID_secp521r1
 *          keyset.add_ec (&key, 1034); // X25519
 *          keyset.add_ec (&key, 1087); // Ed25519
 *          keyset.add_oct (&key, 32);  // 32 bytes
 *          // load from JWK, PEM
 *          json_web_key jwk;
 *          jwk.load_file (&key, "rfc7515.jwk", 0);
 *          jwk.load_pem_file (&key, "test.pem");
 */
class crypto_key
{
public:
    crypto_key ();
    ~crypto_key ();

    /*
     * @brief add
     * @param crypto_key_object_t key [in]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.h)
     */
    return_t add (crypto_key_object_t key, bool up_ref = false);
    /*
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.h)
     */
    return_t add (EVP_PKEY* key, const char* kid = nullptr, bool up_ref = false);
    /*
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.h)
     */
    return_t add (EVP_PKEY* key, const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief generate
     * @param crypto_key_t type [in] CRYPTO_KEY_TYPE
     * @param unsigned int param [in] CRYPTO_KEY_HMAC in bytes
     *                                CRYPTO_KEY_RSA in bits
     *                                CRYPTO_KEY_EC 256, 384, 521
     *                                CRYPTO_KEY_OKP 25518, 448
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.h)
     * @remarks
     *          key.generate (CRYPTO_KEY_HMAC, 32,    "kid", crypto_use_t::use_any); // oct
     *          key.generate (CRYPTO_KEY_RSA,  2048,  "kid", crypto_use_t::use_any); // RSA
     *          key.generate (CRYPTO_KEY_EC,   256,   "kid", crypto_use_t::use_any); // EC, P-256
     *          key.generate (CRYPTO_KEY_EC,   384,   "kid", crypto_use_t::use_any); // EC, P-384
     *          key.generate (CRYPTO_KEY_EC,   521,   "kid", crypto_use_t::use_any); // EC, P-521
     *          key.generate (CRYPTO_KEY_OKP,  25519, "kid", crypto_use_t::use_any); // OKP, X25519 *
     *          key.generate (CRYPTO_KEY_OKP,  448,   "kid", crypto_use_t::use_any); // OKP, X448 *
     *          key.generate (CRYPTO_KEY_OKP,  25519, "kid", CRYPTO_USE_ENC); // OKP, X25519
     *          key.generate (CRYPTO_KEY_OKP,  448,   "kid", CRYPTO_USE_ENC); // OKP, X448
     *          key.generate (CRYPTO_KEY_OKP,  25519, "kid", CRYPTO_USE_SIG); // OKP, Ed25519
     *          key.generate (CRYPTO_KEY_OKP,  448,   "kid", CRYPTO_USE_SIG); // OKP, Ed448
     */
    return_t generate (crypto_key_t type, unsigned int param, const char* kid, crypto_use_t use = crypto_use_t::use_any);

    /*
     * @brief return any key
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* any (bool up_ref = false);
    /*
     * @brief find
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param crypt_alg_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypt_alg_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypt_sig_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param std::string& kid [out]
     * @param crypt_alg_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypt_alg_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param std::string& kid [out]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param const char* kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param const char* kid [in]
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param const char* kid [in]
     * @param crypt_alg_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypt_alg_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /*
     * @brief find
     * @param const char* kid [in]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);

    /*
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     */
    static return_t get_public_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2);
    /*
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& priv [out]
     */
    static return_t get_private_key (EVP_PKEY* pkey, binary_t& priv);
    /*
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv);
    /*
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv);
    /*
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @param crypto_key_t type [out] CRYPTO_KEY_HMAC, CRYPTO_KEY_RSA, CRYPTO_KEY_EC
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, int flag, crypto_key_t& type,
                             binary_t& pub1, binary_t& pub2, binary_t& priv);


    /*
     * @brief clear
     * @remarks decrement a reference counter of keys and clear a container
     */
    void clear ();
    /*
     * size
     */
    size_t size ();

    int addref ();
    int release ();

    /**
     * @brief dump
     * @sample
     *  void dump_crypto_key (crypto_key_object_t* key, void*)
     *  {
     *      uint32 nid = 0;
     *      nidof_evp_pkey (key->pkey, nid);
     *      printf ("nid %i kid %s alg %s use %i\n", nid, key->kid.c_str (), key->alg.c_str (), key->use);
     *  }
     *  void load_key_and_dump ()
     *  {
     *      crypto_key key;
     *      json_web_key jwk;
     *      jwk.load_file (&key, "rfc7515.jwk", 0);
     *      key.for_each (dump_crypto_key, nullptr);
     *  }
     */
    void for_each (void (*)(crypto_key_object_t*, void*), void* param);

protected:
    /*
     * @brief extract
     * @param EVP_PKEY* pkey [in]
     * @param CRYPTO_KEY_FLAG flag [in] CRYPTO_KEY_PUBLIC, CRYPTO_KEY_PRIVATE
     * @param crypto_key_t type [out]
     * @param crypt_datamap_t& datamap [out]
     */
    static return_t extract (EVP_PKEY* pkey, int flag, crypto_key_t& type, crypt_datamap_t& datamap);

private:
    /*
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
    typedef std::multimap<std::string, crypto_key_object_t> crypto_key_map_t;
    crypto_key_map_t _key_map;

    critical_section _lock;
    t_shared_reference <crypto_key> _shared;
};

/*
 * key generator (RSA, EC, HMAC)
 */
class crypto_keychain
{
public:
    /*
     * @brief constructor
     */
    crypto_keychain ();
    /*
     * @brief destructor
     */
    ~crypto_keychain ();

    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.h)
     * @sample
     *    crypto_keychain keyset;
     *    std::string kid;
     *    EVP_PKEY* pkey1 = nullptr, pkey2 = nullptr;
     *    keygen.add_rsa(&crypto_key, "kid.1", 2048);
     *    keygen.add_rsa(&crypto_key, "kid.2", 2048);
     *    pkey1 = crypto_key.find_first_of(CRYPTO_KEY_RSA, kid);
     *    pkey2 = crypto_key.get_by_name(CRYPTO_KEY_RSA, "kid.2");
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param size_t bits [in] 1024, 2048, ...
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, size_t bits, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t n [in]
     * @param binary_t e [in]
     * @param binary_t d [inopt]
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, binary_t n, binary_t e, binary_t d,
                      crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [inopt]
     * @param binary_t n [in]
     * @param binary_t e [in]
     * @param binary_t d [inopt]
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, binary_t n, binary_t e, binary_t d,
                      crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t n [in]
     * @param binary_t e [in]
     * @param binary_t d [inopt]
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, binary_t n, binary_t e, binary_t d,
                      binary_t p, binary_t q, binary_t dp, binary_t dq, binary_t qi, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate rsa key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param binary_t n [in]
     * @param binary_t e [in]
     * @param binary_t d [inopt]
     * @param binary_t p [inopt]
     * @param binary_t q [inopt]
     * @param binary_t dp [inopt]
     * @param binary_t dq [inopt]
     * @param binary_t qi [inopt]
     * @return error code (see error.h)
     */
    return_t add_rsa (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, binary_t n, binary_t e, binary_t d,
                      binary_t p, binary_t q, binary_t dp, binary_t dq, binary_t qi, crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, int nid, crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @return error code (see error.h)
     * @sample
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
     *      EVP_PKEY* alicePrivateKey = (EVP_PKEY*) keys.get_by_name (CRYPTO_KEY_EC, "alice");
     *      EVP_PKEY* bobPrivateKey = (EVP_PKEY*) keys.get_by_name (CRYPTO_KEY_EC, "bob");
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
    return_t add_ec (crypto_key* cryptokey, const char* kid, int nid, crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, const char* kid, const char* alg, int nid, crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, const char* kid, int nid, binary_t x, binary_t y, binary_t d,
                     crypto_use_t use = crypto_use_t::use_any);
    /*
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
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t y, binary_t d,
                     crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
     */
    return_t add_ec_nid_EC (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t y, binary_t d,
                            crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate Ed25519, Ed448
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param int nid [in]
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
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
    return_t add_ec_nid_OKP (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t d,
                             crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate ec key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param int nid [in]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @param binary_t x [in]
     * @param binary_t y [in]
     * @param binary_t d [inopt] private key
     * @return error code (see error.h)
     */
    return_t add_ec (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, int nid, binary_t x, binary_t y, binary_t d,
                     crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param binary_t k [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, binary_t k, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param binary_t k [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, binary_t k, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param binary_t k [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, const char* alg, binary_t k, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param binary_t k [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, binary_t k, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, const char* alg, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param size_t size [in] bytes
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, const byte_t* k, size_t size, crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param const char* alg [inopt]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.h)
     * @sample
     *          const char* passphrase = "password";
     *          keygen.add_oct (&key, nullptr, CRYPT_ALG_PBES2_HS256_A128KW, (byte_t*) passphrase, strlen (passphrase), CRYPTO_USE_ENC);
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* k, size_t size,
                      crypto_use_t use = crypto_use_t::use_any);
    /*
     * @brief generate hmac key
     * @param crypto_key* cryptokey [in]
     * @param const char* kid [inopt]
     * @param crypt_alg_t alg [in]
     * @param const byte_t* k [in]
     * @param size_t size [in]
     * @return error code (see error.h)
     */
    return_t add_oct (crypto_key* cryptokey, const char* kid, crypt_alg_t alg, const byte_t* k, size_t size,
                      crypto_use_t use = crypto_use_t::use_any);

protected:
};

/*
 * @param crypto_key_object_t key [in]
 */
crypto_key_t typeof_crypto_key (crypto_key_object_t key);
/*
 * @brief compare
 * @param EVP_PKEY* pkey [in]
 * @param crypto_key_t type [in]
 */
bool is_kindof (EVP_PKEY* pkey, crypto_key_t type);

}
}  // namespace

#endif

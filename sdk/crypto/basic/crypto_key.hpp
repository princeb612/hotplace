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

#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

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

/**
 * @brief RSA, EC, oct key container
 * @remarks
 *          crypto_key key;
 *          // generate a key
 *          key.generate (crypto_key_t::kty_rsa, 1024, "key1");
 *          key.generate (crypto_key_t::kty_hmac, 32, "key1");
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

    /**
     * @brief load PEM from the buffer
     * @param const char* buffer [in]
     * @param int flags [in]
     * @return error code (see error.hpp)
     */
    return_t load_pem (const char* buffer, int flags, crypto_use_t use);
    /**
     * @brief load from a PEM file
     * @param const char* file [in]
     * @param int flags [in] reserved
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     */
    return_t load_pem_file (const char* file, int flags, crypto_use_t use = crypto_use_t::use_any);
    /**
     * @brief write PEM to the file
     * @param const char* file [in]
     * @param int flag [in] reserved
     * @return error code (see error.hpp)
     */
    return_t write_pem_file (const char* file, int flags = 0);

    /**
     * @brief add
     * @param crypto_key_object_t key [in]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add (crypto_key_object_t key, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add (EVP_PKEY* key, const char* kid = nullptr, bool up_ref = false);
    /**
     * @brief add
     * @param EVP_PKEY* key [in]
     * @param const char* kid [inopt]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt] false by default
     * @return error code (see error.hpp)
     */
    return_t add (EVP_PKEY* key, const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief generate
     * @param crypto_key_t type [in] CRYPTO_KEY_TYPE
     * @param unsigned int param [in] crypto_key_t::kty_hmac in bytes
     *                                crypto_key_t::kty_rsa in bits
     *                                crypto_key_t::kty_ec 256, 384, 521
     *                                crypto_key_t::kty_okp 25518, 448
     * @param const char* kid [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any by default
     * @return error code (see error.hpp)
     * @remarks
     *          key.generate (crypto_key_t::kty_hmac, 32,    "kid", crypto_use_t::use_any); // oct
     *          key.generate (crypto_key_t::kty_rsa,  2048,  "kid", crypto_use_t::use_any); // RSA
     *          key.generate (crypto_key_t::kty_ec,   256,   "kid", crypto_use_t::use_any); // EC, P-256
     *          key.generate (crypto_key_t::kty_ec,   384,   "kid", crypto_use_t::use_any); // EC, P-384
     *          key.generate (crypto_key_t::kty_ec,   521,   "kid", crypto_use_t::use_any); // EC, P-521
     *          key.generate (crypto_key_t::kty_okp,  25519, "kid", crypto_use_t::use_any); // OKP, X25519 *
     *          key.generate (crypto_key_t::kty_okp,  448,   "kid", crypto_use_t::use_any); // OKP, X448 *
     *          key.generate (crypto_key_t::kty_okp,  25519, "kid", crypto_use_t::use_enc); // OKP, X25519
     *          key.generate (crypto_key_t::kty_okp,  448,   "kid", crypto_use_t::use_enc); // OKP, X448
     *          key.generate (crypto_key_t::kty_okp,  25519, "kid", crypto_use_t::use_sig); // OKP, Ed25519
     *          key.generate (crypto_key_t::kty_okp,  448,   "kid", crypto_use_t::use_sig); // OKP, Ed448
     */
    return_t generate (crypto_key_t type, unsigned int param, const char* kid, crypto_use_t use = crypto_use_t::use_any);

    /**
     * @brief return any key
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* any (bool up_ref = false);
    /**
     * @brief find
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (crypt_sig_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (jws_t sig, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param std::string& kid [out]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* select (std::string& kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [out]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypto_key_t kty [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypto_key_t kty, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jwa_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, jwa_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param crypt_sig_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, crypt_sig_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);
    /**
     * @brief find
     * @param const char* kid [in]
     * @param jws_t alg [in]
     * @param crypto_use_t use [inopt] crypto_use_t::use_any
     * @param bool up_ref [inopt]
     */
    EVP_PKEY* find (const char* kid, jws_t alg, crypto_use_t use = crypto_use_t::use_any, bool up_ref = false);

    /**
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     */
    static return_t get_public_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2);
    /**
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& priv [out]
     */
    static return_t get_private_key (EVP_PKEY* pkey, binary_t& priv);
    /**
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv);
    /**
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv);
    /**
     * @brief public key
     * @param EVP_PKEY* pkey [in]
     * @param int flag [in] 0 public only, 1 also private
     * @param crypto_key_t type [out] crypto_key_t::kty_hmac, crypto_key_t::kty_rsa, crypto_key_t::kty_ec
     * @parambinary_t& pub1 [out]
     * @parambinary_t& pub2 [out]
     * @parambinary_t& priv [out]
     */
    static return_t get_key (EVP_PKEY* pkey, int flag, crypto_key_t& type,
                             binary_t& pub1, binary_t& pub2, binary_t& priv);


    /**
     * @brief clear
     * @remarks decrement a reference counter of keys and clear a container
     */
    void clear ();
    /**
     * size
     */
    size_t size ();

    int addref ();
    int release ();

    /**
     * @brief dump
     * @example
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
    /**
     * @brief extract
     * @param EVP_PKEY* pkey [in]
     * @param CRYPTO_KEY_FLAG flag [in] CRYPTO_KEY_PUBLIC, CRYPTO_KEY_PRIVATE
     * @param crypto_key_t type [out]
     * @param crypt_datamap_t& datamap [out]
     */
    static return_t extract (EVP_PKEY* pkey, int flag, crypto_key_t& type, crypt_datamap_t& datamap);

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
    typedef std::multimap<std::string, crypto_key_object_t> crypto_key_map_t;
    crypto_key_map_t _key_map;

    critical_section _lock;
    t_shared_reference <crypto_key> _shared;
};

/**
 * @param crypto_key_object_t key [in]
 */
crypto_key_t typeof_crypto_key (crypto_key_object_t const& key);
/**
 * @brief compare
 * @param EVP_PKEY* pkey [in]
 * @param crypto_key_t type [in]
 */
bool is_kindof (EVP_PKEY* pkey, crypto_key_t type);

}
}  // namespace

#endif
